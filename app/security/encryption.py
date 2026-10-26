"""Encryption-at-rest and deterministic hashing helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

TOTP_DERIVATION_LABEL = b"secure-login-v2:totp-secret:v1"
RECOVERY_DERIVATION_LABEL = b"secure-login-v2:recovery-code:v1"


class SecretDecryptionError(RuntimeError):
    """Raised without exposing ciphertext or key material."""


def _derive_key(label: bytes, source: str) -> bytes:
    digest = hashlib.sha256(label + b":" + source.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet() -> Fernet:
    key = current_app.config["TOTP_ENCRYPTION_KEY"]
    return Fernet(_derive_key(TOTP_DERIVATION_LABEL, key))


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise SecretDecryptionError("Stored secret cannot be decrypted.") from exc


def _recovery_key() -> bytes:
    # Prefer an independent recovery pepper when configured.
    source = current_app.config.get("RECOVERY_CODE_PEPPER") or current_app.config[
        "SECRET_KEY"
    ]
    return _derive_key(RECOVERY_DERIVATION_LABEL, str(source))


def normalise_recovery_code(code: str) -> str:
    return "".join(character for character in code.upper() if character.isalnum())


def hash_recovery_code(code: str) -> str:
    normalised = normalise_recovery_code(code)
    return hmac.new(
        _recovery_key(),
        normalised.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_recovery_codes(count: int = 10) -> list[str]:
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(10).upper()
        codes.append("-".join(raw[index : index + 4] for index in range(0, 20, 4)))
    return codes
