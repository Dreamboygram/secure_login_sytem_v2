"""High-level test helpers for realistic login flows."""

from __future__ import annotations

import pyotp

from app.extensions import db
from app.models.user import User
from app.security.encryption import decrypt_secret


def login_with_password(client, csrf, username, password):
    token = csrf.for_path(client, "/auth/login")
    return client.post(
        "/auth/login",
        data={
            "csrf_token": token,
            "identifier": username,
            "password": password,
        },
        follow_redirects=False,
    )


def login_with_totp(client, csrf, username, password, secret, *, counter=None):
    response = login_with_password(client, csrf, username, password)
    assert response.status_code == 302, response.get_data(as_text=True)
    assert "/auth/verify-2fa" in response.headers["Location"]

    token = csrf.for_path(client, "/auth/verify-2fa")
    totp = pyotp.TOTP(secret)
    code = totp.generate_otp(counter) if counter is not None else totp.now()
    return client.post(
        "/auth/verify-2fa",
        data={"csrf_token": token, "code": code},
        follow_redirects=False,
    )


def get_totp_secret(user_id):
    user = db.session.get(User, user_id)
    assert user is not None and user.totp_secret_enc
    return decrypt_secret(user.totp_secret_enc)
