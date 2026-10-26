"""User-friendly HTTP error handlers that never expose internals."""

from __future__ import annotations

from flask import current_app, render_template, request
from werkzeug.exceptions import HTTPException

from app.extensions import db

_DEFAULT_MESSAGES = {
    400: "The request could not be processed.",
    401: "Authentication is required to access this page.",
    403: "You do not have permission to access this page.",
    404: "The requested page could not be found.",
    405: "That action is not allowed here.",
    413: "The submitted request is too large.",
    429: "Too many requests. Please wait and try again.",
    500: "An unexpected error occurred. Please try again later.",
    503: "The service is temporarily unavailable.",
}

_TITLES = {
    400: "Bad request",
    401: "Authentication required",
    403: "Access denied",
    404: "Page not found",
    405: "Method not allowed",
    413: "Request too large",
    429: "Too many requests",
    500: "Server error",
    503: "Service unavailable",
}


def _render_error(status_code: int, *, message: str | None = None):
    return (
        render_template(
            "errors/error.html",
            code=status_code,
            title=_TITLES.get(status_code, "Error"),
            message=message or _DEFAULT_MESSAGES.get(status_code, "Request failed."),
        ),
        status_code,
    )


def register_error_handlers(app) -> None:
    @app.errorhandler(400)
    def bad_request(error):
        return _render_error(400)

    @app.errorhandler(401)
    def unauthorized(error):
        return _render_error(401)

    @app.errorhandler(403)
    def forbidden(error):
        return _render_error(403)

    @app.errorhandler(404)
    def not_found(error):
        return _render_error(404)

    @app.errorhandler(413)
    def request_too_large(error):
        return _render_error(413)

    @app.errorhandler(429)
    def rate_limited(error):
        return _render_error(429)

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        original = getattr(error, "original_exception", None)
        current_app.logger.error(
            "Unhandled server error on endpoint %s",
            request.endpoint or "unknown",
            exc_info=original if isinstance(original, BaseException) else True,
        )
        return _render_error(500)

    @app.errorhandler(HTTPException)
    def http_exception(error):
        status = error.code or 500
        if status not in _DEFAULT_MESSAGES:
            message = (
                "The request could not be completed."
                if status < 500
                else "An unexpected error occurred. Please try again later."
            )
            return _render_error(status, message=message)
        return _render_error(status)
