"""One-time administrator bootstrap tests."""

from __future__ import annotations

import secrets

from app.extensions import db
from app.models.roles import Role
from app.models.user import User
from app.security.passwords import generate_temporary_password, validate_password_policy
from tests.helpers import login_with_password


def _strong_password() -> str:
    for _ in range(20):
        password = generate_temporary_password(24)
        if not validate_password_policy(
            password,
            username="Cisco",
            email="cisco@example.com",
        ):
            return password
    raise AssertionError("Could not generate a policy-compliant test password")


def _runner(app):
    return app.test_cli_runner()


def test_create_admin_requires_bootstrap_token(app, monkeypatch):
    monkeypatch.delenv("BOOTSTRAP_TOKEN", raising=False)

    result = _runner(app).invoke(
        args=[
            "create-admin",
            "--username",
            "Cisco",
            "--email",
            "cisco@example.com",
        ]
    )

    assert result.exit_code != 0
    assert "BOOTSTRAP_TOKEN" in result.output
    assert db.session.scalar(
        db.select(User).where(db.func.lower(User.username) == "cisco")
    ) is None


def test_create_admin_rejects_wrong_bootstrap_token(app, monkeypatch):
    monkeypatch.setenv("BOOTSTRAP_TOKEN", secrets.token_urlsafe(32))

    result = _runner(app).invoke(
        args=[
            "create-admin",
            "--username",
            "Cisco",
            "--email",
            "cisco@example.com",
        ],
        input="definitely-the-wrong-token\n",
    )

    assert result.exit_code != 0
    assert "Bootstrap authorisation failed" in result.output
    assert db.session.scalar(
        db.select(User).where(db.func.lower(User.username) == "cisco")
    ) is None


def test_create_admin_is_one_time_and_forces_password_change_and_2fa(
    app, client, csrf, monkeypatch
):
    bootstrap_token = secrets.token_urlsafe(32)
    password = _strong_password()
    monkeypatch.setenv("BOOTSTRAP_TOKEN", bootstrap_token)

    result = _runner(app).invoke(
        args=[
            "create-admin",
            "--username",
            "Cisco",
            "--email",
            "cisco@example.com",
        ],
        input=f"{bootstrap_token}\n{password}\n{password}\n",
    )

    assert result.exit_code == 0, result.output
    user = db.session.scalar(
        db.select(User).where(db.func.lower(User.username) == "cisco")
    )
    assert user is not None
    assert user.role.name == "ADMINISTRATOR"
    assert user.is_active is True
    assert user.must_change_password is True
    assert user.totp_enabled is False
    assert user.requires_2fa_setup is True
    assert user.password_hash.startswith("$argon2id$")
    assert password not in user.password_hash

    response = login_with_password(client, csrf, "Cisco", password)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/change-password")

    second_result = _runner(app).invoke(
        args=[
            "create-admin",
            "--username",
            "AnotherAdmin",
            "--email",
            "another-admin@example.com",
        ],
        input=f"{bootstrap_token}\n",
    )

    assert second_result.exit_code != 0
    assert "An administrator already exists" in second_result.output
    assert db.session.scalar(
        db.select(db.func.count())
        .select_from(User)
        .join(Role)
        .where(Role.name == "ADMINISTRATOR")
    ) == 1
