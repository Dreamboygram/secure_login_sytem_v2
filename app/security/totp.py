"""TOTP generation, QR provisioning, and replay-safe verification."""

from __future__ import annotations

import base64
import hmac
import io
import time
from dataclasses import dataclass

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage


@dataclass(frozen=True)
class TOTPResult:
    valid: bool
    counter: int | None = None
    reason: str = ""


def create_totp_secret() -> str:
    return pyotp.random_base32(length=32)


def current_counter(interval: int = 30) -> int:
    return int(time.time() // interval)


def build_provisioning_uri(secret: str, *, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def qr_code_data_uri(provisioning_uri: str) -> str:
    image = qrcode.make(
        provisioning_uri,
        image_factory=SvgPathImage,
        box_size=7,
        border=2,
    )
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def verify_totp_code(
    secret: str,
    code: str,
    *,
    last_counter: int = -1,
    interval: int = 30,
    digits: int = 6,
    valid_window: int = 1,
) -> TOTPResult:
    candidate = "".join(character for character in code.strip() if character.isdigit())
    if len(candidate) != digits or not code.strip().isdigit():
        return TOTPResult(False, reason="format")

    current = current_counter(interval)
    totp = pyotp.TOTP(secret, interval=interval, digits=digits)
    for offset in range(-abs(valid_window), abs(valid_window) + 1):
        counter = current + offset
        expected = totp.generate_otp(counter)
        if hmac.compare_digest(candidate, expected):
            if counter <= int(last_counter):
                return TOTPResult(False, counter=counter, reason="replay")
            return TOTPResult(True, counter=counter)
    return TOTPResult(False, reason="mismatch")
