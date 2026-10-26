"""Password policy checks. No password is ever logged or stored here."""

from __future__ import annotations

import re
import unicodedata

COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password123",
        "password123!",
        "admin",
        "administrator",
        "letmein",
        "welcome",
        "welcome1",
        "qwerty123",
        "changeme",
        "changeme123",
        "iloveyou",
        "monkey123",
        "dragon123",
        "football1",
        "baseball1",
        "123456789012",
        "1234567890123",
    }
)

_EMAIL_LOCAL_RE = re.compile(r"^[^@]+")


def _contains_identifier(password: str, identifier: str) -> bool:
    candidate = unicodedata.normalize("NFKC", identifier).strip().lower()
    if len(candidate) < 4:
        return False
    return candidate in unicodedata.normalize("NFKC", password).lower()


def password_policy_errors(
    password: str,
    *,
    username: str = "",
    email: str = "",
    minimum_length: int = 12,
    maximum_length: int = 128,
) -> list[str]:
    errors: list[str] = []
    if "\x00" in password:
        return ["Password contains an invalid character."]
    if len(password) < minimum_length:
        errors.append(f"Password must be at least {minimum_length} characters long.")
    if len(password) > maximum_length:
        errors.append(f"Password must be no more than {maximum_length} characters long.")

    checks = {
        "an uppercase letter": any(character.isupper() for character in password),
        "a lowercase letter": any(character.islower() for character in password),
        "a number": any(character.isdigit() for character in password),
        "a special character": any(
            not character.isalnum() for character in password
        ),
    }
    missing = [label for label, passed in checks.items() if not passed]
    if missing:
        errors.append("Password must include " + ", ".join(missing) + ".")

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        errors.append("Password is too common. Choose a different password.")
    if username and _contains_identifier(password, username):
        errors.append("Password must not contain the username.")
    if email:
        local_part = _EMAIL_LOCAL_RE.match(email)
        if local_part and _contains_identifier(password, local_part.group(0)):
            errors.append("Password must not contain the email address.")
    if re.search(r"(.)\1{3,}", password):
        errors.append("Password must not repeat the same character four times.")
    return errors
