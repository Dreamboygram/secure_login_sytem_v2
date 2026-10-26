"""Argon2id password hashing with an application-level, versioned pepper."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import current_app

from app.security.passwords_policy import password_policy_errors

PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

_SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}:,.?"
_DUMMY_HASHES: dict[int, str] = {}


class PasswordConfigurationError(RuntimeError):
    """Raised when pepper configuration cannot satisfy a hashing request."""


def _pepper_for_version(version: int) -> str:
    peppers: dict[int, str] = current_app.config["PASSWORD_PEPPERS"]
    pepper = peppers.get(int(version))
    if not pepper:
        raise PasswordConfigurationError(
            "No password pepper is configured for the stored hash version."
        )
    return pepper


def _peppered_password(password: str, version: int) -> str:
    pepper = _pepper_for_version(version)
    return hmac.new(
        pepper.encode("utf-8"),
        password.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_password(password: str) -> tuple[str, int]:
    """Hash a password and return (encoded hash, pepper version)."""
    version = int(current_app.config["PASSWORD_PEPPER_VERSION"])
    encoded = PASSWORD_HASHER.hash(_peppered_password(password, version))
    return encoded, version


def verify_password(
    password: str, encoded_hash: str, pepper_version: int
) -> bool:
    try:
        peppered = _peppered_password(password, pepper_version)
        return PASSWORD_HASHER.verify(encoded_hash, peppered)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except PasswordConfigurationError:
        return False


def verify_dummy_password(password: str) -> None:
    """Spend comparable time when an account identifier does not exist."""
    version = int(current_app.config["PASSWORD_PEPPER_VERSION"])
    dummy_hash = _DUMMY_HASHES.get(version)
    if dummy_hash is None:
        dummy_hash = PASSWORD_HASHER.hash(
            _peppered_password("not-a-real-user-password", version)
        )
        _DUMMY_HASHES[version] = dummy_hash
    try:
        PASSWORD_HASHER.verify(dummy_hash, _peppered_password(password, version))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pass


def password_needs_rehash(encoded_hash: str, pepper_version: int) -> bool:
    current_version = int(current_app.config["PASSWORD_PEPPER_VERSION"])
    if int(pepper_version) != current_version:
        return True
    try:
        return PASSWORD_HASHER.check_needs_rehash(encoded_hash)
    except (InvalidHashError, VerificationError):
        return True


def upgrade_password_hash(user, password: str) -> bool:
    """Rehash a successfully verified password using the current pepper."""
    if not password_needs_rehash(user.password_hash, user.password_pepper_version):
        return False
    encoded, version = hash_password(password)
    user.password_hash = encoded
    user.password_pepper_version = version
    return True


def validate_password_policy(
    password: str, *, username: str = "", email: str = ""
) -> list[str]:
    return password_policy_errors(
        password,
        username=username,
        email=email,
        minimum_length=int(current_app.config["PASSWORD_MIN_LENGTH"]),
        maximum_length=int(current_app.config["PASSWORD_MAX_LENGTH"]),
    )


def generate_temporary_password(length: int = 20) -> str:
    """Generate a policy-compliant temporary credential."""
    if length < 16:
        length = 16
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(_SPECIAL_CHARACTERS),
    ]
    alphabet = string.ascii_letters + string.digits + _SPECIAL_CHARACTERS
    required.extend(secrets.choice(alphabet) for _ in range(length - len(required)))
    secrets.SystemRandom().shuffle(required)
    return "".join(required)
