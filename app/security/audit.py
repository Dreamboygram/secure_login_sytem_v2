"""Security audit and login-attempt recording with sensitive-field filtering."""

from __future__ import annotations

import json
from typing import Any

from flask import has_request_context, request

from app.extensions import db
from app.models.security import AuditLog, LoginAttempt

_SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "hash",
    "pepper",
    "cookie",
    "session",
    "code",
)


def _client_ip() -> str | None:
    if not has_request_context():
        return None
    value = request.remote_addr
    return value[:45] if value else None


def _user_agent() -> str | None:
    if not has_request_context():
        return None
    value = request.headers.get("User-Agent", "")
    return value[:255] or None


def _sanitise_details(details: dict[str, Any] | None) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    if not details:
        return safe
    for key, value in details.items():
        key_text = str(key)[:64]
        if any(part in key_text.lower() for part in _SENSITIVE_KEY_PARTS):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key_text] = value if not isinstance(value, str) else value[:500]
        elif isinstance(value, (list, tuple)):
            safe[key_text] = [str(item)[:100] for item in value[:20]]
        else:
            safe[key_text] = str(value)[:200]
    return safe


def log_event(
    action: str,
    *,
    actor_user_id: int | None = None,
    target_user_id: int | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        action=action[:80],
        outcome=outcome[:16],
        details=json.dumps(_sanitise_details(details), ensure_ascii=True),
        ip_address=_client_ip(),
        user_agent=_user_agent(),
    )
    db.session.add(entry)
    return entry


def record_login_attempt(
    *,
    identifier: str,
    successful: bool,
    reason: str,
    user_id: int | None = None,
    attempt_type: str = "password",
) -> LoginAttempt:
    attempt = LoginAttempt(
        user_id=user_id,
        identifier=(identifier or "")[:255],
        attempt_type=attempt_type[:20],
        successful=successful,
        reason=reason[:64],
        ip_address=_client_ip(),
        user_agent=_user_agent(),
    )
    db.session.add(attempt)
    return attempt
