"""Two-factor setup, verification, replay, recovery, and lockout tests."""

from __future__ import annotations

import re
import time

import pyotp

import app.security.totp as totp_module
from app.extensions import db
from app.models.security import RecoveryCode
from app.models.user import User
from tests.conftest import TEST_PASSWORD
from tests.helpers import get_totp_secret, login_with_password, login_with_totp


def _fixed_totp_time(monkeypatch):
    counter = int(time.time() // 30)
    monkeypatch.setattr(totp_module, "current_counter", lambda interval=30: counter)
    return counter


def test_setup_enables_2fa_and_shows_only_hashed_recovery_codes(
    app, client, csrf, user_factory, monkeypatch
):
    user_id = user_factory(username="setupuser")
    login_with_password(client, csrf, "setupuser", TEST_PASSWORD)
    counter = _fixed_totp_time(monkeypatch)

    client.get("/auth/2fa/setup")
    page = client.get("/auth/2fa/setup")
    if page.status_code != 200:
        page = client.get("/auth/2fa/setup")
    if page.status_code != 200:
        page = client.get("/auth/2fa/setup")
    assert page.status_code == 200
    token = csrf.from_response(page)
    secret = get_totp_secret(user_id)
    code = pyotp.TOTP(secret).generate_otp(counter)
    response = client.post(
        "/auth/2fa/setup",
        data={"csrf_token": token, "code": code},
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    displayed_codes = re.findall(r"<li><code>([^<]+)</code></li>", html)
    assert len(displayed_codes) == 10

    db.session.expire_all()
    user = db.session.get(User, user_id)
    assert user.totp_enabled is True
    assert user.totp_secret_enc is not None
    assert secret not in user.totp_secret_enc
    codes = list(
        db.session.scalars(
            db.select(RecoveryCode).where(RecoveryCode.user_id == user_id)
        )
    )
    assert len(codes) == 10
    assert all(re.fullmatch(r"[0-9a-f]{64}", item.code_hash) for item in codes)
    assert not any(item.code_hash == displayed_codes[0] for item in codes)


def test_correct_totp_completes_login(app, client, csrf, user_factory):
    secret = pyotp.random_base32()
    user_factory(username="totpuser", totp_secret=secret)

    response = login_with_totp(
        client, csrf, "totpuser", TEST_PASSWORD, secret
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
    assert client.get("/records").status_code == 200
    with client.session_transaction() as session:
        assert "pre_2fa_user_id" not in session


def test_incorrect_totp_is_rejected_and_counted(
    app, client, csrf, user_factory, monkeypatch
):
    counter = _fixed_totp_time(monkeypatch)
    secret = pyotp.random_base32()
    user_id = user_factory(username="badtotp", totp_secret=secret)
    response = login_with_password(client, csrf, "badtotp", TEST_PASSWORD)
    assert response.status_code == 302

    correct = pyotp.TOTP(secret).generate_otp(counter)
    wrong = f"{(int(correct) + 1) % 1_000_000:06d}"
    token = csrf.for_path(client, "/auth/verify-2fa")
    response = client.post(
        "/auth/verify-2fa",
        data={"csrf_token": token, "code": wrong},
    )

    assert response.status_code == 401
    user = db.session.get(User, user_id)
    assert user.two_factor_failed_count == 1
    assert not user.is_two_factor_locked


def test_totp_replay_is_rejected_after_successful_login(
    app, client, csrf, user_factory, monkeypatch
):
    counter = _fixed_totp_time(monkeypatch)
    secret = pyotp.random_base32()
    user_id = user_factory(username="replayuser", totp_secret=secret)
    code = pyotp.TOTP(secret).generate_otp(counter)

    response = login_with_totp(
        client, csrf, "replayuser", TEST_PASSWORD, secret, counter=counter
    )
    assert response.status_code == 302
    assert db.session.get(User, user_id).totp_last_counter == counter

    token = csrf.for_path(client, "/records")
    client.post("/auth/logout", data={"csrf_token": token})

    response = login_with_password(client, csrf, "replayuser", TEST_PASSWORD)
    assert response.status_code == 302
    token = csrf.for_path(client, "/auth/verify-2fa")
    response = client.post(
        "/auth/verify-2fa",
        data={"csrf_token": token, "code": code},
    )

    assert response.status_code == 401
    assert db.session.get(User, user_id).two_factor_failed_count == 1


def test_recovery_code_is_single_use(app, client, csrf, user_factory):
    secret = pyotp.random_base32()
    recovery_code = "ABCD-EFGH-IJKL-MNOP-QRST"
    user_id = user_factory(
        username="recoveryuser",
        totp_secret=secret,
        recovery_code=recovery_code,
    )

    response = login_with_password(client, csrf, "recoveryuser", TEST_PASSWORD)
    assert response.status_code == 302
    token = csrf.for_path(client, "/auth/verify-2fa")
    response = client.post(
        "/auth/verify-2fa",
        data={"csrf_token": token, "code": recovery_code},
    )

    assert response.status_code == 302
    stored = db.session.scalar(
        db.select(RecoveryCode).where(RecoveryCode.user_id == user_id)
    )
    assert stored.used_at is not None

    token = csrf.for_path(client, "/records")
    client.post("/auth/logout", data={"csrf_token": token})
    login_with_password(client, csrf, "recoveryuser", TEST_PASSWORD)
    token = csrf.for_path(client, "/auth/verify-2fa")
    response = client.post(
        "/auth/verify-2fa",
        data={"csrf_token": token, "code": recovery_code},
    )
    assert response.status_code == 401


def test_totp_bruteforce_lockout_blocks_valid_code(
    app, client, csrf, user_factory, monkeypatch
):
    counter = _fixed_totp_time(monkeypatch)
    secret = pyotp.random_base32()
    user_id = user_factory(username="locktotp", totp_secret=secret)
    login_with_password(client, csrf, "locktotp", TEST_PASSWORD)
    token = csrf.for_path(client, "/auth/verify-2fa")
    correct = pyotp.TOTP(secret).generate_otp(counter)

    for attempt in range(1, 6):
        wrong = f"{(int(correct) + attempt) % 1_000_000:06d}"
        response = client.post(
            "/auth/verify-2fa",
            data={"csrf_token": token, "code": wrong},
        )
        assert response.status_code == 401

    user = db.session.get(User, user_id)
    assert user.is_two_factor_locked

    response = client.post(
        "/auth/verify-2fa",
        data={"csrf_token": token, "code": correct},
    )
    assert response.status_code == 401
    assert client.get("/records", follow_redirects=False).status_code == 302


def test_inputer_can_disable_own_2fa(app, client, csrf, user_factory):
    secret = pyotp.random_base32()
    user_id = user_factory(username="disableuser", totp_secret=secret)
    login_with_totp(client, csrf, "disableuser", TEST_PASSWORD, secret)

    token = csrf.for_path(client, "/auth/account")
    next_counter = int(time.time() // 30) + 1
    code = pyotp.TOTP(secret).generate_otp(next_counter)
    response = client.post(
        "/auth/2fa/disable",
        data={
            "csrf_token": token,
            "password": TEST_PASSWORD,
            "code": code,
        },
    )

    assert response.status_code == 302
    user = db.session.get(User, user_id)
    assert user.totp_enabled is False
    assert user.totp_secret_enc is None
    assert db.session.scalar(
        db.select(db.func.count())
        .select_from(RecoveryCode)
        .where(RecoveryCode.user_id == user_id)
    ) == 0


def test_privileged_account_cannot_disable_2fa(
    app, client, csrf, user_factory
):
    secret = pyotp.random_base32()
    user_factory(username="secureadmin", role_name="ADMINISTRATOR", totp_secret=secret)
    login_with_totp(client, csrf, "secureadmin", TEST_PASSWORD, secret)

    token = csrf.for_path(client, "/admin/")
    response = client.post(
        "/auth/2fa/disable",
        data={
            "csrf_token": token,
            "password": TEST_PASSWORD,
            "code": "000000",
        },
    )
    assert response.status_code == 403
