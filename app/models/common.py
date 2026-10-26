"""Shared model helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return naive UTC for consistent SQLite/PostgreSQL storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc).isoformat()
