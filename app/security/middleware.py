"""Request/response security middleware."""

from __future__ import annotations

import time

from flask import current_app, flash, redirect, request, session, url_for
from flask_login import current_user, logout_user

from app.extensions import login_manager

_ALLOWED_DURING_PASSWORD_CHANGE = frozenset(
    {
        "static",
        "health.health",
        "auth.logout",
        "auth.change_password",
    }
)

_ALLOWED_DURING_2FA_SETUP = frozenset(
    {
        "static",
        "health.health",
        "auth.logout",
        "auth.change_password",
        "auth.setup_2fa",
    }
)


def _clear_authenticated_session(message: str):
    logout_user()
    session.clear()
    flash(message, "warning")
    return redirect(url_for("auth.login"))


def register_security_middleware(app) -> None:
    @app.before_request
    def enforce_transport_security():
        if (
            app.config.get("ENFORCE_HTTPS")
            and not app.config.get("TESTING")
            and not request.is_secure
            and request.endpoint != "health.health"
        ):
            return redirect(
                request.url.replace("http://", "https://", 1),
                code=308,
            )
        return None

    @app.before_request
    def enforce_authenticated_account_state():
        if request.endpoint == "static" or not current_user.is_authenticated:
            return None

        if not current_user.is_active:
            return _clear_authenticated_session(
                "Your account is not available. Contact an administrator."
            )

        session_version = session.get("auth_version")
        if session_version is None or int(session_version) != int(
            current_user.auth_version
        ):
            return _clear_authenticated_session(
                "Your session is no longer valid. Sign in again."
            )

        now = time.time()
        idle_limit = int(
            current_app.permanent_session_lifetime.total_seconds()
        )
        last_activity = session.get("last_activity")
        if last_activity is not None:
            try:
                elapsed = now - float(last_activity)
            except (TypeError, ValueError):
                elapsed = idle_limit + 1
            if elapsed > idle_limit:
                return _clear_authenticated_session(
                    "Your session expired due to inactivity. Sign in again."
                )
        session["last_activity"] = now

        if current_user.must_change_password:
            if request.endpoint not in _ALLOWED_DURING_PASSWORD_CHANGE:
                flash("Change your temporary password before continuing.", "warning")
                return redirect(url_for("auth.change_password"))
            return None

        if current_user.requires_2fa_setup:
            if request.endpoint not in _ALLOWED_DURING_2FA_SETUP:
                flash("Set up two-factor authentication before continuing.", "warning")
                return redirect(url_for("auth.setup_2fa"))
        return None

    @app.after_request
    def apply_security_headers(response):
        for header, value in app.config.get("SECURITY_HEADERS", {}).items():
            response.headers.setdefault(header, value)
        if app.config.get("ENFORCE_HTTPS") and not app.config.get("TESTING"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )

        if request.endpoint == "static":
            response.headers.setdefault(
                "Cache-Control", "public, max-age=3600"
            )
        elif (
            request.path.startswith(("/auth", "/dashboard", "/admin", "/records"))
            or current_user.is_authenticated
            or response.status_code >= 400
        ):
            response.headers["Cache-Control"] = "no-store"
            response.headers.setdefault("Pragma", "no-cache")
        return response

    login_manager.session_protection = "strong"
