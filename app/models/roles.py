"""Role and permission models backed by the central RBAC matrix."""

from __future__ import annotations

from app.extensions import db
from app.models.common import utcnow
from app.security.rbac import role_has_permission


role_permissions = db.Table(
    "role_permissions",
    db.Column(
        "role_id",
        db.Integer,
        db.ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "permission_id",
        db.Integer,
        db.ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False)

    roles = db.relationship(
        "Role",
        secondary=role_permissions,
        back_populates="permissions",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Permission {self.code}>"


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False, default="")
    rank = db.Column(db.Integer, nullable=False, default=0, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    permissions = db.relationship(
        "Permission",
        secondary=role_permissions,
        back_populates="roles",
        lazy="selectin",
    )
    users = db.relationship("User", back_populates="role", lazy="dynamic")

    @property
    def permission_codes(self) -> set[str]:
        return {permission.code for permission in self.permissions}

    def has_permission(self, code: str) -> bool:
        return code in self.permission_codes and role_has_permission(self.name, code)

    def __repr__(self) -> str:
        return f"<Role {self.name}>"
