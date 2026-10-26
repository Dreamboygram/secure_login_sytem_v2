"""PostgreSQL regression coverage for the two-factor row lock."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import psycopg
import pyotp
import pytest
from flask import g
from flask_migrate import upgrade
from psycopg import sql
from sqlalchemy import event
from sqlalchemy.engine import make_url

from app import create_app
from app.extensions import db
from app.models.common import utcnow
from app.models.roles import Role
from app.models.user import User
from app.security.encryption import encrypt_secret
from app.security.passwords import hash_password
from tests.helpers import login_with_password, login_with_totp


ROOT = Path(__file__).resolve().parent.parent


def _schema_url(database_url: str, schema: str) -> str:
    parsed = make_url(database_url)
    query = dict(parsed.query)
    query["options"] = f"-csearch_path={schema}"
    return parsed.set(query=query).render_as_string(hide_password=False)


@pytest.fixture
def postgres_app():
    database_url = os.getenv("TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("TEST_POSTGRES_URL is not configured")

    schema = f"test_2fa_{secrets.token_hex(8)}"
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))

    app = create_app(
        "testing",
        {
            "SQLALCHEMY_DATABASE_URI": _schema_url(database_url, schema),
            "SQLALCHEMY_ENGINE_OPTIONS": {},
        },
        load_env=False,
    )

    @app.after_request
    def clear_request_scoped_test_caches(response):
        g.pop("csrf_token", None)
        g.pop("_login_user", None)
        return response

    context = app.app_context()
    context.push()
    try:
        upgrade(directory=str(ROOT / "migrations"))
        yield app
    finally:
        db.session.remove()
        db.engine.dispose()
        context.pop()
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema)
                )
            )


def test_postgres_2fa_login_locks_only_users_row(postgres_app, csrf):
    client = postgres_app.test_client()
    username = "postgres2fa"
    password = secrets.token_urlsafe(24)
    secret = pyotp.random_base32()
    role = db.session.scalar(db.select(Role).where(Role.name == "INPUTER"))
    assert role is not None
    encoded, version = hash_password(password)
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=encoded,
        password_pepper_version=version,
        role=role,
        is_active=True,
        must_change_password=False,
        totp_secret_enc=encrypt_secret(secret),
        totp_enabled=True,
        totp_confirmed_at=utcnow(),
    )
    db.session.add(user)
    db.session.commit()
    user_id = user.id
    code = pyotp.TOTP(secret).now()
    lock_statements = []

    def capture_lock_statements(
        connection, cursor, statement, parameters, context, executemany
    ):
        if "FOR UPDATE" in statement.upper():
            lock_statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", capture_lock_statements)
    try:
        response = login_with_totp(client, csrf, username, password, secret)
    finally:
        event.remove(db.engine, "before_cursor_execute", capture_lock_statements)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
    assert client.get("/records").status_code == 200
    assert len(lock_statements) == 1
    lock_sql = lock_statements[0].upper()
    assert "FOR UPDATE OF USERS" in lock_sql
    assert "JOIN" not in lock_sql

    db.session.expire_all()
    assert db.session.get(User, user_id).totp_last_counter >= 0

    token = csrf.for_path(client, "/records")
    client.post("/auth/logout", data={"csrf_token": token})

    response = login_with_password(client, csrf, username, password)
    assert response.status_code == 302
    token = csrf.for_path(client, "/auth/verify-2fa")
    response = client.post(
        "/auth/verify-2fa",
        data={"csrf_token": token, "code": code},
    )
    assert response.status_code == 401

    db.session.expire_all()
    assert db.session.get(User, user_id).two_factor_failed_count == 1
