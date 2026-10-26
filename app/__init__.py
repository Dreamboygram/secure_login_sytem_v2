"""Secure Login System V2 application factory."""

from __future__ import annotations

from dotenv import load_dotenv
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from app.cli import register_cli
from app.config import BASE_DIR, INSTANCE_DIR, get_config, validate_runtime_config
from app.errors import register_error_handlers
from app.extensions import csrf, db, limiter, login_manager, migrate
from app.logging_config import configure_logging
from app.security.middleware import register_security_middleware

__all__ = ["create_app"]


def create_app(
    env_name: str | None = None,
    test_config: dict | None = None,
    *,
    load_env: bool = True,
) -> Flask:
    if load_env:
        load_dotenv(BASE_DIR / ".env", override=False)

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(env_name))
    if test_config:
        app.config.update(test_config)

    validate_runtime_config(app)
    configure_logging(app)
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

    proxy_count = int(app.config.get("TRUSTED_PROXY_COUNT") or 0)
    if proxy_count:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=proxy_count,
            x_proto=proxy_count,
            x_host=proxy_count,
            x_port=proxy_count,
        )

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)

    # Import all model modules after the extension is bound. This is needed for
    # migrations and relationship resolution, and does not create tables.
    from app import models  # noqa: F401

    from app.admin.routes import bp as admin_bp
    from app.auth.routes import bp as auth_bp
    from app.dashboard.routes import bp as dashboard_bp
    from app.public import health_bp, public_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            from app.models.user import User

            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @login_manager.unauthorized_handler
    def unauthorized():
        from flask import flash, redirect, request, url_for

        flash("Please sign in to continue.", "warning")
        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))

    @app.context_processor
    def inject_template_globals():
        from datetime import datetime, timezone

        return {
            "app_name": "Secure Login System V2",
            "current_year": datetime.now(timezone.utc).year,
        }

    @app.template_filter("utc")
    def format_utc(value):
        if value is None:
            return "Never"
        return value.strftime("%Y-%m-%d %H:%M UTC")

    @app.template_filter("pretty_json")
    def pretty_json(value):
        import json

        try:
            return json.dumps(json.loads(value), indent=2, ensure_ascii=True)
        except (TypeError, ValueError):
            return "{}"

    @app.errorhandler(405)
    def method_not_allowed(error):
        from app.errors.handlers import _render_error

        return _render_error(405, message="That action is not allowed here.")

    register_error_handlers(app)
    register_security_middleware(app)
    register_cli(app)

    return app
