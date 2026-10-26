"""Authentication, account, lockout, and session behaviour tests."""

from __future__ import annotations

import pyotp

from app.extensions import db
from app.models.security import LoginAttempt
from app.models.user import User
from app.security.passwords import hash_password
from tests.conftest import NEW_PASSWORD, TEST_PASSWORD
from tests.helpers import get_totp_secret, login_with_password


def test_registration_creates_inputer_with_argon2_hash(app, client, csrf):
    token = csrf.for_path(client, "/auth/register")
    response = client.post(
        "/auth/register",
        data={
            "csrf_token": token,
            "username": "New.Inputer",
            "email": "new.inputer@example.com",
            "password": TEST_PASSWORD,
            "confirm_password": TEST_PASSWORD,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")
    user = db.session.scalar(db.select(User).where(User.username == "new.inputer"))
    assert user is not None
    assert user.role.name == "INPUTER"
    assert user.password_hash.startswith("$argon2id$")
    assert TEST_PASSWORD not in user.password_hash
    assert user.is_active is True


def test_registration_rejects_weak_composition(app, client, csrf):
    token = csrf.for_path(client, "/auth/register")
    response = client.post(
        "/auth/register",
        data={
            "csrf_token": token,
            "username": "weakuser",
            "email": "weak@example.com",
            "password": "alllowercase123",
            "confirm_password": "alllowercase123",
        },
    )

    assert response.status_code == 200
    assert "password must" in response.get_data(as_text=True).lower()
    assert db.session.scalar(db.select(User).where(User.username == "weakuser")) is None


def test_password_hashes_are_salted_and_pepper_dependent(app):
    first, version = hash_password(TEST_PASSWORD)
    second, _ = hash_password(TEST_PASSWORD)
    assert first != second
    assert first.startswith("$argon2id$")
    assert version == app.config["PASSWORD_PEPPER_VERSION"]


def test_case_insensitive_login_and_authenticated_page(app, client, csrf, user_factory):
    user_factory(username="Cisco", role_name="INPUTER")

    response = login_with_password(client, csrf, "CISCO", TEST_PASSWORD)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
    page = client.get("/records")
    assert page.status_code == 200
    assert "cisco" in page.get_data(as_text=True).lower()


def test_invalid_password_is_generic_and_counted(app, client, csrf, user_factory):
    user_id = user_factory(username="counted")

    response = login_with_password(client, csrf, "counted", "Wrong-Password!2026")

    assert response.status_code == 401
    page = response.get_data(as_text=True)
    assert "Invalid username/email or password" in page
    user = db.session.get(User, user_id)
    assert user.failed_login_count == 1
    assert db.session.scalar(
        db.select(db.func.count())
        .select_from(LoginAttempt)
        .where(
            LoginAttempt.user_id == user_id,
            LoginAttempt.successful.is_(False),
        )
    ) == 1


def test_five_failures_lock_account_even_with_correct_password(
    app, client, csrf, user_factory
):
    user_id = user_factory(username="locked")

    token = csrf.for_path(client, "/auth/login")
    for _ in range(5):
        response = client.post(
            "/auth/login",
            data={
                "csrf_token": token,
                "identifier": "locked",
                "password": "Wrong-Password!2026",
            },
        )
        assert response.status_code == 401

    user = db.session.get(User, user_id)
    assert user.failed_login_count == 5
    assert user.locked_until is not None
    assert user.is_locked

    response = login_with_password(client, csrf, "locked", TEST_PASSWORD)
    assert response.status_code == 401
    assert db.session.get(User, user_id).is_locked


def test_inactive_account_uses_generic_failure(app, client, csrf, user_factory):
    user_factory(username="inactive", is_active=False)

    response = login_with_password(client, csrf, "inactive", TEST_PASSWORD)

    assert response.status_code == 401
    assert "Invalid username/email or password" in response.get_data(as_text=True)


def test_password_change_updates_hash_and_clears_temporary_flag(
    app, client, csrf, user_factory
):
    user_id = user_factory(
        username="changer",
        must_change_password=True,
    )
    login_response = login_with_password(client, csrf, "changer", TEST_PASSWORD)
    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/auth/change-password")

    token = csrf.for_path(client, "/auth/change-password")
    response = client.post(
        "/auth/change-password",
        data={
            "csrf_token": token,
            "current_password": TEST_PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/account")
    user = db.session.get(User, user_id)
    assert user.must_change_password is False
    assert user.password_hash != hash_password(TEST_PASSWORD)[0]
    assert client.get("/auth/account").status_code == 200


def test_session_idle_timeout_clears_session(app, client, csrf, user_factory):
    user_id = user_factory(username="idle")
    response = login_with_password(client, csrf, "idle", TEST_PASSWORD)
    assert response.status_code == 302

    with client.session_transaction() as session:
        session["last_activity"] = 0

    response = client.get("/auth/account", follow_redirects=False)

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
    with client.session_transaction() as session:
        assert "_user_id" not in session
        assert "auth_version" not in session


def test_csrf_rejects_login_without_token(client):
    response = client.post(
        "/auth/login",
        data={"identifier": "someone", "password": "Some-Password!2026"},
    )
    assert response.status_code == 400
    assert "Bad request" in response.get_data(as_text=True)


def test_logout_requires_post_and_clears_session(app, client, csrf, user_factory):
    user_factory(username="leaver")
    login_with_password(client, csrf, "leaver", TEST_PASSWORD)

    token = csrf.for_path(client, "/auth/account")
    response = client.post(
        "/auth/logout",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")

    response = client.get("/records", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_login_rate_limit_blocks_eleventh_attempt(app_factory, csrf):
    application = app_factory(RATELIMIT_ENABLED=True, RATE_LIMIT_STORAGE_URI="memory://")
    test_client = application.test_client()
    token = csrf.for_path(test_client, "/auth/login")
    statuses = []

    for attempt in range(1, 12):
        response = test_client.post(
            "/auth/login",
            data={
                "csrf_token": token,
                "identifier": f"unknown-{attempt}",
                "password": "Wrong-Password!2026",
            },
        )
        statuses.append(response.status_code)

    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429


def test_pre_two_factor_session_expires(app, client, csrf, user_factory):
    secret = pyotp.random_base32()
    user_factory(username="pending", totp_secret=secret)
    response = login_with_password(client, csrf, "pending", TEST_PASSWORD)
    assert response.status_code == 302

    with client.session_transaction() as session:
        session["pre_2fa_started"] = 0

    response = client.get("/auth/verify-2fa", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")
