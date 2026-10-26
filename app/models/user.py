"""User account model."""

from __future__ import annotations

from datetime import datetime

from flask_login import UserMixin

from app.extensions import db
from app.models.common import utcnow
from app.security.rbac import role_has_permission, role_is_privileged


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    password_pepper_version = db.Column(db.Integer, nullable=False, default=1)
    role_id = db.Column(
        db.Integer,
        db.ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)

    totp_secret_enc = db.Column(db.Text, nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_confirmed_at = db.Column(db.DateTime, nullable=True)
    totp_last_counter = db.Column(db.BigInteger, nullable=False, default=-1)
    two_factor_failed_count = db.Column(db.Integer, nullable=False, default=0)
    two_factor_locked_until = db.Column(db.DateTime, nullable=True)

    auth_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    role = db.relationship("Role", back_populates="users", lazy="joined")
    recovery_codes = db.relationship(
        "RecoveryCode",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @property
    def role_name(self) -> str:
        return self.role.name if self.role else ""

    @property
    def is_privileged(self) -> bool:
        return role_is_privileged(self.role_name)

    @property
    def requires_2fa_setup(self) -> bool:
        return self.is_privileged and not self.totp_enabled

    @property
    def account_status(self) -> str:
        if not self.is_active:
            return "Deactivated"
        if self.is_locked:
            return "Locked"
        return "Active"

    @property
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > utcnow())

    @property
    def is_two_factor_locked(self) -> bool:
        return bool(
            self.two_factor_locked_until and self.two_factor_locked_until > utcnow()
        )

    def has_permission(self, code: str) -> bool:
        if not self.is_active or not self.role:
            return False
        return self.role.has_permission(code) and role_has_permission(
            self.role_name, code
        )

    def invalidate_sessions(self) -> None:
        self.auth_version = int(self.auth_version or 0) + 1

    def __repr__(self) -> str:
        return f"<User {self.id} {self.username}>"
