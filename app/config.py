"""Application configuration with fail-closed production validation."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or unsafe."""


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _required(name: str) -> str:
    value = _env(name)
    if not value:
        raise ConfigurationError(f"Required environment variable {name} is not set.")
    return value


def _env_int(name: str, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer.") from exc
    if value < minimum or (maximum is not None and value > maximum):
        raise ConfigurationError(f"{name} is outside the allowed range.")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    normalised = raw.lower()
    if normalised in {"1", "true", "yes", "on"}:
        return True
    if normalised in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false.")


def _secret(name: str, minimum_length: int = 32) -> str:
    value = _required(name)
    if len(value) < minimum_length:
        raise ConfigurationError(
            f"{name} must contain at least {minimum_length} characters."
        )
    return value


def _normalise_database_url(url: str, *, production: bool) -> str:
    value = url.strip()
    if value.startswith("postgres://"):
        value = "postgresql+psycopg://" + value[len("postgres://") :]
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value[len("postgresql://") :]

    if production:
        if not value.startswith("postgresql+psycopg://"):
            raise ConfigurationError(
                "Production DATABASE_URL must use PostgreSQL. SQLite fallback is disabled."
            )
    elif not value:
        raise ConfigurationError("DATABASE_URL must not be empty.")
    return value


def _database_url(production: bool) -> str:
    if production:
        return _normalise_database_url(_required("DATABASE_URL"), production=True)

    configured = _env("DATABASE_URL")
    if configured:
        return _normalise_database_url(configured, production=False)
    return "sqlite:///" + (INSTANCE_DIR / "secure_login_v2.db").as_posix()


def _pepper_map() -> tuple[dict[int, str], int]:
    current_version = _env_int("PASSWORD_PEPPER_VERSION", 1, minimum=1)
    peppers: dict[int, str] = {}

    for name, value in os.environ.items():
        if not name.startswith("PASSWORD_PEPPER_V"):
            continue
        suffix = name[len("PASSWORD_PEPPER_V") :]
        if not suffix.isdigit():
            continue
        version = int(suffix)
        if value and len(value) >= 32:
            peppers[version] = value

    current = _env("PASSWORD_PEPPER")
    if current:
        if len(current) < 32:
            raise ConfigurationError(
                "PASSWORD_PEPPER must contain at least 32 characters."
            )
        peppers[current_version] = current

    if current_version not in peppers:
        raise ConfigurationError(
            "The current PASSWORD_PEPPER version has no matching pepper value."
        )
    return peppers, current_version


class BaseConfig:
    ENV_NAME = "development"
    TESTING = False
    DEBUG = False

    def __init__(self) -> None:
        self.FLASK_ENV = self.ENV_NAME
        self.SECRET_KEY = _secret("FLASK_SECRET_KEY")
        self.PASSWORD_PEPPERS, self.PASSWORD_PEPPER_VERSION = _pepper_map()
        self.TOTP_ENCRYPTION_KEY = _secret("TOTP_ENCRYPTION_KEY")
        self.RECOVERY_CODE_PEPPER = _secret("RECOVERY_CODE_PEPPER")
        self.SQLALCHEMY_DATABASE_URI = _database_url(production=False)

        self.SESSION_COOKIE_NAME = "secure_login_v2_session"
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
        self.SESSION_REFRESH_EACH_REQUEST = True
        self.PERMANENT_SESSION_LIFETIME = timedelta(
            minutes=_env_int(
                "PERMANENT_SESSION_LIFETIME_MINUTES", 30, minimum=5, maximum=1440
            )
        )
        self.REMEMBER_COOKIE_HTTPONLY = True
        self.REMEMBER_COOKIE_SAMESITE = "Lax"
        self.REMEMBER_COOKIE_SECURE = self.SESSION_COOKIE_SECURE

        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_pre_ping": True,
            "pool_recycle": 280,
        }
        self.MAX_CONTENT_LENGTH = 1024 * 1024
        self.WTF_CSRF_TIME_LIMIT = 3600
        self.WTF_CSRF_SSL_STRICT = True

        self.LOG_LEVEL = (_env("LOG_LEVEL", "INFO") or "INFO").upper()
        self.TRUSTED_PROXY_COUNT = _env_int("TRUSTED_PROXY_COUNT", 1, minimum=0, maximum=5)
        self.PREFERRED_URL_SCHEME = "http"
        self.ENFORCE_HTTPS = False

        self.LOGIN_MAX_FAILED_ATTEMPTS = _env_int(
            "LOGIN_MAX_FAILED_ATTEMPTS", 5, minimum=3, maximum=20
        )
        self.LOGIN_LOCKOUT_MINUTES = _env_int(
            "LOGIN_LOCKOUT_MINUTES", 15, minimum=1, maximum=1440
        )
        self.TOTP_MAX_FAILED_ATTEMPTS = _env_int(
            "TOTP_MAX_FAILED_ATTEMPTS", 5, minimum=3, maximum=20
        )
        self.TOTP_LOCKOUT_MINUTES = _env_int(
            "TOTP_LOCKOUT_MINUTES", 15, minimum=1, maximum=1440
        )
        self.TOTP_INTERVAL = 30
        self.TOTP_DIGITS = 6
        self.TOTP_VALID_WINDOW = 1
        self.TOTP_ISSUER = _env("TOTP_ISSUER", "Secure Login System V2")
        self.PRE_2FA_LIFETIME = timedelta(minutes=5)
        self.PASSWORD_MIN_LENGTH = 12
        self.PASSWORD_MAX_LENGTH = 128
        self.RECOVERY_CODE_COUNT = 10

        self.RATELIMIT_STORAGE_URI = _env("RATELIMIT_STORAGE_URI", "memory://")
        self.RATELIMIT_ENABLED = _env_bool("RATELIMIT_ENABLED", True)
        self.RATELIMIT_HEADERS_ENABLED = True
        self.RATELIMIT_STRATEGY = "fixed-window"

        self.PASSWORD_RESET_TTL_HOURS = 24

        self.SECURITY_HEADERS = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "img-src 'self' data:; "
                "style-src 'self'; "
                "script-src 'self'; "
                "font-src 'self'; "
                "object-src 'none'"
            ),
        }


class DevelopmentConfig(BaseConfig):
    ENV_NAME = "development"


class TestingConfig(BaseConfig):
    ENV_NAME = "testing"
    TESTING = True
    DEBUG = False

    def __init__(self) -> None:
        # Deliberately isolated test-only values. They are not usable secrets
        # for a deployed application.
        self.FLASK_ENV = "testing"
        self.SECRET_KEY = "test-only-session-signing-key-not-for-production"
        self.PASSWORD_PEPPERS = {1: "test-only-password-pepper-not-for-production"}
        self.PASSWORD_PEPPER_VERSION = 1
        self.TOTP_ENCRYPTION_KEY = "test-only-totp-encryption-key-not-for-production"
        self.RECOVERY_CODE_PEPPER = "test-only-recovery-code-pepper-not-for-production"
        self.SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

        self.SESSION_COOKIE_NAME = "secure_login_v2_test_session"
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.SESSION_COOKIE_SECURE = False
        self.SESSION_REFRESH_EACH_REQUEST = True
        self.PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
        self.REMEMBER_COOKIE_HTTPONLY = True
        self.REMEMBER_COOKIE_SAMESITE = "Lax"
        self.REMEMBER_COOKIE_SECURE = False

        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {}
        self.MAX_CONTENT_LENGTH = 1024 * 1024
        self.WTF_CSRF_TIME_LIMIT = 3600
        self.WTF_CSRF_SSL_STRICT = False

        self.LOG_LEVEL = "WARNING"
        self.TRUSTED_PROXY_COUNT = 0
        self.PREFERRED_URL_SCHEME = "http"
        self.ENFORCE_HTTPS = False

        self.LOGIN_MAX_FAILED_ATTEMPTS = 5
        self.LOGIN_LOCKOUT_MINUTES = 15
        self.TOTP_MAX_FAILED_ATTEMPTS = 5
        self.TOTP_LOCKOUT_MINUTES = 15
        self.TOTP_INTERVAL = 30
        self.TOTP_DIGITS = 6
        self.TOTP_VALID_WINDOW = 1
        self.TOTP_ISSUER = "Secure Login System V2 Test"
        self.PRE_2FA_LIFETIME = timedelta(minutes=5)
        self.PASSWORD_MIN_LENGTH = 12
        self.PASSWORD_MAX_LENGTH = 128
        self.RECOVERY_CODE_COUNT = 10

        self.RATELIMIT_STORAGE_URI = "memory://"
        self.RATELIMIT_ENABLED = False
        self.RATELIMIT_HEADERS_ENABLED = True
        self.RATELIMIT_STRATEGY = "fixed-window"

        self.PASSWORD_RESET_TTL_HOURS = 24
        self.SECURITY_HEADERS = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Content-Security-Policy": (
                "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
                "form-action 'self'; img-src 'self' data:; style-src 'self'; "
                "script-src 'self'; font-src 'self'; object-src 'none'"
            ),
        }


class ProductionConfig(BaseConfig):
    ENV_NAME = "production"

    def __init__(self) -> None:
        super().__init__()
        self.DEBUG = False
        self.TESTING = False
        self.PREFERRED_URL_SCHEME = "https"
        self.ENFORCE_HTTPS = True
        self.SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", True)
        self.REMEMBER_COOKIE_SECURE = self.SESSION_COOKIE_SECURE
        self.SQLALCHEMY_DATABASE_URI = _database_url(production=True)

        if not self.SESSION_COOKIE_SECURE:
            raise ConfigurationError(
                "SESSION_COOKIE_SECURE must be true in production."
            )
        if self.DEBUG:
            raise ConfigurationError("Debug mode must be disabled in production.")


def get_config(env_name: str | None = None):
    environment = (
        env_name or os.getenv("FLASK_ENV") or os.getenv("APP_ENV") or "development"
    ).strip().lower()
    if environment == "production":
        return ProductionConfig()
    if environment in {"test", "testing"}:
        return TestingConfig()
    if environment in {"dev", "development"}:
        return DevelopmentConfig()
    raise ConfigurationError("FLASK_ENV must be development, testing, or production.")


def validate_runtime_config(app) -> None:
    """Validate invariants after overrides have been applied."""
    if app.config.get("TESTING"):
        return

    if app.config.get("FLASK_ENV") == "production":
        if app.debug:
            raise ConfigurationError("Debug mode must be disabled in production.")
        if not app.config.get("SESSION_COOKIE_SECURE"):
            raise ConfigurationError(
                "SESSION_COOKIE_SECURE must be true in production."
            )
        uri = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
        if not uri.startswith("postgresql+psycopg://"):
            raise ConfigurationError(
                "Production requires PostgreSQL via DATABASE_URL."
            )
        for key in (
            "SECRET_KEY",
            "TOTP_ENCRYPTION_KEY",
            "RECOVERY_CODE_PEPPER",
        ):
            if len(str(app.config.get(key, ""))) < 32:
                raise ConfigurationError(f"{key} is not configured securely.")
        peppers = app.config.get("PASSWORD_PEPPERS") or {}
        current = app.config.get("PASSWORD_PEPPER_VERSION")
        if current not in peppers or len(peppers[current]) < 32:
            raise ConfigurationError("The active password pepper is invalid.")
