"""Public landing page and lightweight health check."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db

public_bp = Blueprint("public", __name__)
health_bp = Blueprint("health", __name__)


@public_bp.get("/")
def home():
    return render_template("public/home.html")


@health_bp.get("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        db.session.rollback()
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.warning(
            "Health check database failure: %s", type(exc).__name__
        )
        response = jsonify({"status": "unhealthy"})
        response.status_code = 503
        response.headers["Cache-Control"] = "no-store"
        return response

    response = jsonify(
        {"status": "ok", "service": "secure-login-system-v2"}
    )
    response.status_code = 200
    response.headers["Cache-Control"] = "no-store"
    return response
