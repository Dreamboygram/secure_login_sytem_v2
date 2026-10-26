"""Shared isolated application and account fixtures."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import create_app
from app.extensions import db, limiter
from app.models.common import utcnow
from app.models.roles import Role
from app.models.security import RecoveryCode
from app.models.user import User
from app.security.encryption import encrypt_secret, hash_recovery_code
from app.security.passwords import hash_password
from app.services.rbac_seed import seed_reference_data

TEST_PASSWORD = "Test-Only-Pass!2026"
NEW_PASSWORD = "Changed-Test-Pass!2026"


def make_test_app(tmp_path: Path, *, suffix: str = "", **overrides):
    database_path = (tmp_path / f"test{suffix}.db").as_posix()
    config = {
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
        "WTF_CSRF_ENABLED": True,
        "RATELIMIT_ENABLED": False,
        "PROPAGATE_EXCEPTIONS": False,
        "SERVER_NAME": "localhost",
    }
    config.update(overrides)
    app = create_app("testing", config, load_env=False)
    with app.app_context():
        db.create_all()
        seed_reference_data()

    from flask import g

    @app.after_request
    def clear_request_scoped_test_caches(response):
        # The tests keep one app context open for database access. Flask-WTF
        # caches CSRF tokens and Flask-Login caches the user on ``g``, which is
        # app-context scoped. Real requests get a fresh app context.
        g.pop("csrf_token", None)
        g.pop("_login_user", None)
        return response

    return app


@pytest.fixture
def app(tmp_path):
    application = make_test_app(tmp_path)
    context = application.app_context()
    context.push()
    yield application
    db.session.remove()
    db.drop_all()
    context.pop()


@pytest.fixture
def app_factory(tmp_path):
    applications = []
    counter = {"value": 0}

    def factory(**overrides):
        counter["value"] += 1
        application = make_test_app(
            tmp_path, suffix=f"-{counter['value']}", **overrides
        )
        applications.append(application)
        return application

    yield factory

    for application in applications:
        with application.app_context():
            db.session.remove()
            db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user_factory(app):
    def create(
        username="inputer",
        *,
        email=None,
        role_name="INPUTER",
        password=TEST_PASSWORD,
        is_active=True,
        must_change_password=False,
        totp_secret=None,
        recovery_code=None,
    ):
        role = db.session.scalar(db.select(Role).where(Role.name == role_name))
        assert role is not None, f"Unknown test role: {role_name}"
        encoded, version = hash_password(password)
        user = User(
            username=username.lower(),
            email=email or f"{username.lower()}@example.com",
            password_hash=encoded,
            password_pepper_version=version,
            role=role,
            is_active=is_active,
            must_change_password=must_change_password,
        )
        if totp_secret is not None:
            user.totp_secret_enc = encrypt_secret(totp_secret)
            user.totp_enabled = True
            user.totp_confirmed_at = utcnow()
        db.session.add(user)
        db.session.flush()
        if recovery_code is not None:
            db.session.add(
                RecoveryCode(
                    user_id=user.id,
                    code_hash=hash_recovery_code(recovery_code),
                )
            )
        db.session.commit()
        return user.id

    return create


@pytest.fixture
def csrf():
    pattern = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')

    def from_response(response):
        match = pattern.search(response.get_data(as_text=True))
        assert match, "Expected a CSRF token in the response HTML"
        return match.group(1)

    def for_path(test_client, path):
        response = test_client.get(path)
        assert response.status_code == 200, f"GET {path} returned {response.status_code}"
        return from_response(response)

    return type(
        "CsrfHelpers",
        (),
        {"from_response": staticmethod(from_response), "for_path": for_path},
    )


@pytest.fixture(autouse=True)
def reset_limiter():
    if getattr(limiter, "_storage", None) is not None:
        limiter.reset()
    yield
    if getattr(limiter, "_storage", None) is not None:
        limiter.reset()
