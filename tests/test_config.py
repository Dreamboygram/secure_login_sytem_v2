"""Database URL configuration tests."""

from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url

from app.config import ConfigurationError, _normalise_database_url

POSTGRES_URL = "postgresql://db.internal:5432/secure_login_v2"


@pytest.mark.parametrize(
    "raw_url",
    [
        POSTGRES_URL,
        POSTGRES_URL.replace("postgresql://", "postgres://", 1),
        f'"{POSTGRES_URL}"',
        f"'{POSTGRES_URL}'",
        f"\ufeff{POSTGRES_URL}",
        f"  {POSTGRES_URL}  ",
    ],
)
def test_postgres_urls_are_normalised_for_psycopg(raw_url):
    normalised = _normalise_database_url(raw_url, production=True)
    parsed = make_url(normalised)

    assert parsed.drivername == "postgresql+psycopg"
    assert parsed.host == "db.internal"
    assert parsed.port == 5432
    assert parsed.database == "secure_login_v2"


def test_malformed_url_fails_with_safe_configuration_error():
    with pytest.raises(ConfigurationError) as exc_info:
        _normalise_database_url("not-a-database-url", production=False)

    assert "not-a-database-url" not in str(exc_info.value)


def test_production_rejects_sqlite():
    with pytest.raises(ConfigurationError):
        _normalise_database_url("sqlite:///local.db", production=True)
