"""Idempotent reference-data seeding for roles and permissions."""

from __future__ import annotations

from app.extensions import db
from app.models.roles import Permission, Role
from app.security.rbac import PERMISSIONS, ROLE_DEFINITIONS


def seed_reference_data(*, commit: bool = True) -> None:
    permissions_by_code: dict[str, Permission] = {}
    for code, description in PERMISSIONS.items():
        permission = db.session.scalar(
            db.select(Permission).where(Permission.code == code)
        )
        if permission is None:
            permission = Permission(code=code, description=description)
            db.session.add(permission)
        else:
            permission.description = description
        permissions_by_code[code] = permission

    db.session.flush()

    for role_name, definition in ROLE_DEFINITIONS.items():
        role = db.session.scalar(db.select(Role).where(Role.name == role_name))
        if role is None:
            role = Role(name=role_name)
            db.session.add(role)
        role.description = definition.description
        role.rank = definition.rank
        role.permissions = [
            permissions_by_code[code] for code in definition.permissions
        ]

    if commit:
        db.session.commit()
