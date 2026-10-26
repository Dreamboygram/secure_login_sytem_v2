"""Security, audit, and recovery models."""

from __future__ import annotations

from app.extensions import db
from app.models.common import utcnow


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    identifier = db.Column(db.String(255), nullable=False, default="")
    attempt_type = db.Column(db.String(20), nullable=False, default="password")
    successful = db.Column(db.Boolean, nullable=False, default=False)
    reason = db.Column(db.String(64), nullable=False, default="")
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


class AuditLog(db.Model):
    __tablename__ = "security_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action = db.Column(db.String(80), nullable=False, index=True)
    outcome = db.Column(db.String(16), nullable=False, default="success")
    details = db.Column(db.Text, nullable=False, default="{}")
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    actor = db.relationship(
        "User", foreign_keys=[actor_user_id], lazy="joined", join_depth=1
    )
    target = db.relationship(
        "User", foreign_keys=[target_user_id], lazy="joined", join_depth=1
    )


class PasswordReset(db.Model):
    __tablename__ = "password_resets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    performed_by_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    method = db.Column(db.String(32), nullable=False, default="administrative")
    reason = db.Column(db.String(255), nullable=False, default="")
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class RecoveryCode(db.Model):
    __tablename__ = "recovery_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    code_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    used_ip = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    user = db.relationship("User", back_populates="recovery_codes")


class AppSetting(db.Model):
    __tablename__ = "app_settings"

    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.String(500), nullable=False, default="")
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
