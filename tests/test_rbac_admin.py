"""Role enforcement, protected accounts, and administrative action tests."""

from __future__ import annotations

import html
import re

import pyotp

from app.extensions import db
from app.models.roles import Role
from app.models.security import RecoveryCode
from app.models.user import User
from app.security.passwords import verify_password
from tests.conftest import TEST_PASSWORD
from tests.helpers import login_with_password, login_with_totp


def _admin_with_totp(user_factory, username="admin"):
    secret = pyotp.random_base32()
    user_id = user_factory(
        username=username,
        role_name="ADMINISTRATOR",
        totp_secret=secret,
    )
    return user_id, secret


def test_anonymous_and_low_privilege_are_denied(app, client, csrf, user_factory):
    response = client.get("/admin/", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    user_factory(username="plaininputer")
    login_with_password(client, csrf, "plaininputer", TEST_PASSWORD)
    assert client.get("/admin/").status_code == 403
    assert client.get("/reports").status_code == 403
    assert client.get("/records").status_code == 200


def test_manager_has_reports_but_not_administration(app, client, csrf, user_factory):
    secret = pyotp.random_base32()
    user_factory(username="manager", role_name="MANAGER", totp_secret=secret)
    login_with_totp(client, csrf, "manager", TEST_PASSWORD, secret)

    assert client.get("/reports").status_code == 200
    assert client.get("/admin/").status_code == 403
    assert client.get("/records").status_code == 403


def test_admin_is_read_only_for_users(app, client, csrf, user_factory):
    secret = pyotp.random_base32()
    user_factory(username="readadmin", role_name="ADMIN", totp_secret=secret)
    login_with_totp(client, csrf, "readadmin", TEST_PASSWORD, secret)

    page = client.get("/admin/users")
    assert page.status_code == 200
    assert "Read only" in page.get_data(as_text=True)

    token = csrf.from_response(page)
    response = client.post(
        "/admin/users/create",
        data={
            "csrf_token": token,
            "username": "forbidden",
            "email": "forbidden@example.com",
            "role_id": 1,
        },
    )
    assert response.status_code == 403
    assert db.session.scalar(db.select(User).where(User.username == "forbidden")) is None


def test_administrator_logs_in_and_creates_user(app, client, csrf, user_factory):
    admin_id, secret = _admin_with_totp(user_factory)
    response = login_with_totp(client, csrf, "admin", TEST_PASSWORD, secret)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")

    dashboard = client.get("/admin/")
    assert dashboard.status_code == 200
    assert "Administrative dashboard" in dashboard.get_data(as_text=True)

    create_page = client.get("/admin/users/create")
    token = csrf.from_response(create_page)
    inputer_role = db.session.scalar(db.select(Role).where(Role.name == "INPUTER"))
    response = client.post(
        "/admin/users/create",
        data={
            "csrf_token": token,
            "username": "createduser",
            "email": "createduser@example.com",
            "role_id": inputer_role.id,
        },
    )

    assert response.status_code == 200
    assert "One-time display" in response.get_data(as_text=True)
    created = db.session.scalar(
        db.select(User).where(User.username == "createduser")
    )
    assert created is not None
    assert created.must_change_password is True
    assert created.role.name == "INPUTER"
    assert created.totp_enabled is False
    assert int(created.password_pepper_version) == app.config["PASSWORD_PEPPER_VERSION"]


def test_higher_rank_account_is_protected(app, client, csrf, user_factory):
    owner_role = Role(
        name="OWNER",
        rank=200,
        description="Test-only higher rank.",
        created_at=db.func.now(),
    )
    db.session.add(owner_role)
    db.session.commit()
    target_id = user_factory(username="owneraccount", role_name="OWNER")
    _admin_id, secret = _admin_with_totp(user_factory)
    login_with_totp(client, csrf, "admin", TEST_PASSWORD, secret)

    page = client.get("/admin/users")
    assert "Protected" in page.get_data(as_text=True)
    token = csrf.from_response(page)
    response = client.post(
        f"/admin/users/{target_id}/toggle",
        data={"csrf_token": token},
    )
    assert response.status_code == 403
    assert db.session.get(User, target_id).is_active is True


def test_administrator_cannot_assign_unknown_higher_role(
    app, client, csrf, user_factory
):
    owner_role = Role(
        name="OWNER",
        rank=200,
        description="Test-only higher rank.",
        created_at=db.func.now(),
    )
    db.session.add(owner_role)
    db.session.commit()
    target_id = user_factory(username="promotiontarget")
    _admin_id, secret = _admin_with_totp(user_factory)
    login_with_totp(client, csrf, "admin", TEST_PASSWORD, secret)

    token = csrf.for_path(client, "/admin/users")
    response = client.post(
        f"/admin/users/{target_id}/role",
        data={"csrf_token": token, "role_id": owner_role.id},
    )

    assert response.status_code == 403
    assert db.session.get(User, target_id).role.name == "INPUTER"


def test_self_role_change_is_blocked(app, client, csrf, user_factory):
    admin_id, secret = _admin_with_totp(user_factory)
    inputer_role = db.session.scalar(db.select(Role).where(Role.name == "INPUTER"))
    login_with_totp(client, csrf, "admin", TEST_PASSWORD, secret)

    token = csrf.for_path(client, "/admin/users")
    response = client.post(
        f"/admin/users/{admin_id}/role",
        data={"csrf_token": token, "role_id": inputer_role.id},
    )

    assert response.status_code == 400
    assert db.session.get(User, admin_id).role.name == "ADMINISTRATOR"


def test_deactivation_invalidates_target_session(
    app, client, csrf, user_factory
):
    target_id = user_factory(username="sessiontarget")
    target_client = app.test_client()
    login_with_password(target_client, csrf, "sessiontarget", TEST_PASSWORD)
    assert target_client.get("/records").status_code == 200

    _admin_id, secret = _admin_with_totp(user_factory)
    admin_client = app.test_client()
    login_with_totp(admin_client, csrf, "admin", TEST_PASSWORD, secret)
    token = csrf.for_path(admin_client, "/admin/users")
    response = admin_client.post(
        f"/admin/users/{target_id}/toggle",
        data={"csrf_token": token},
    )
    assert response.status_code == 302

    response = target_client.get("/records", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_administrator_password_reset_requires_reauth_and_invalidates_sessions(
    app, client, csrf, user_factory
):
    target_id = user_factory(username="resetme")
    target_client = app.test_client()
    login_with_password(target_client, csrf, "resetme", TEST_PASSWORD)
    old_version = db.session.get(User, target_id).auth_version
    _admin_id, secret = _admin_with_totp(user_factory)
    login_with_totp(client, csrf, "admin", TEST_PASSWORD, secret)

    token = csrf.for_path(client, "/admin/users")
    wrong = client.post(
        f"/admin/users/{target_id}/reset-password",
        data={
            "csrf_token": token,
            "current_password": "Wrong-Admin-Pass!2026",
            "reason": "User requested a reset",
        },
    )
    assert wrong.status_code == 400
    assert db.session.get(User, target_id).auth_version == old_version

    token = csrf.for_path(client, f"/admin/users/{target_id}/reset-password")
    response = client.post(
        f"/admin/users/{target_id}/reset-password",
        data={
            "csrf_token": token,
            "current_password": TEST_PASSWORD,
            "reason": "User requested a reset",
        },
    )

    assert response.status_code == 200
    match = re.search(
        r'id="reset-temporary-password">([^<]+)</code>',
        response.get_data(as_text=True),
    )
    assert match
    temporary_password = html.unescape(match.group(1))
    target = db.session.get(User, target_id)
    assert target.must_change_password is True
    assert target.auth_version > old_version
    assert verify_password(
        temporary_password, target.password_hash, target.password_pepper_version
    )

    response = target_client.get("/records", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_administrator_2fa_reset_removes_secret_and_recovery_codes(
    app, client, csrf, user_factory
):
    target_secret = pyotp.random_base32()
    target_id = user_factory(
        username="reset2fauser",
        totp_secret=target_secret,
        recovery_code="ZZZZ-YYYY-XXXX-WWWW-VVVV",
    )
    _admin_id, secret = _admin_with_totp(user_factory)
    login_with_totp(client, csrf, "admin", TEST_PASSWORD, secret)

    token = csrf.for_path(client, f"/admin/users/{target_id}/reset-2fa")
    response = client.post(
        f"/admin/users/{target_id}/reset-2fa",
        data={
            "csrf_token": token,
            "current_password": TEST_PASSWORD,
            "reason": "Lost authenticator device",
        },
    )

    assert response.status_code == 302
    target = db.session.get(User, target_id)
    assert target.totp_enabled is False
    assert target.totp_secret_enc is None
    assert db.session.scalar(
        db.select(db.func.count())
        .select_from(RecoveryCode)
        .where(RecoveryCode.user_id == target_id)
    ) == 0
