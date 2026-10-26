"""seed roles and permissions

Revision ID: a396af622d7c
Revises: 2cd3cea18532
Create Date: 2026-10-26 23:38:30.000000

Reference data is immutable in this migration. Future changes should add a new
migration and synchronise through the seed-rbac command.
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = "a396af622d7c"
down_revision = "2cd3cea18532"
branch_labels = None
depends_on = None


PERMISSIONS = [
    ("dashboard.view", "Access the authenticated dashboard."),
    ("account.security", "Manage own password and two-factor settings."),
    ("records.view_own", "View own operational records."),
    ("records.manage_own", "Create and update own operational records."),
    ("records.moderate", "View and moderate operational records."),
    ("admin.view", "Access the administrative dashboard."),
    ("users.view", "View the user directory."),
    ("users.manage", "Create, deactivate, and manage user accounts."),
    ("roles.assign", "Assign permitted roles to users."),
    ("audit.view", "Review security audit activity."),
    ("security.manage", "Perform controlled security recovery actions."),
    ("manager.view", "Access the management dashboard."),
    ("reports.view", "View authorised operational reports."),
]

ROLES = [
    (
        "INPUTER",
        10,
        "Operational data entry and own-record management.",
        (
            "dashboard.view",
            "account.security",
            "records.view_own",
            "records.manage_own",
        ),
    ),
    (
        "MANAGER",
        40,
        "Management reporting and operational oversight.",
        ("dashboard.view", "account.security", "manager.view", "reports.view"),
    ),
    (
        "ADMIN",
        60,
        "Administrative oversight without account administration.",
        (
            "dashboard.view",
            "account.security",
            "admin.view",
            "users.view",
            "audit.view",
            "records.moderate",
        ),
    ),
    (
        "ADMINISTRATOR",
        100,
        "Full account, role, and security administration.",
        (
            "dashboard.view",
            "account.security",
            "admin.view",
            "users.view",
            "users.manage",
            "roles.assign",
            "audit.view",
            "security.manage",
            "records.moderate",
        ),
    ),
]


def upgrade():
    bind = op.get_bind()
    permissions = sa.table(
        "permissions",
        sa.column("id", sa.Integer),
        sa.column("code", sa.String),
        sa.column("description", sa.String),
    )
    roles = sa.table(
        "roles",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
        sa.column("rank", sa.Integer),
        sa.column("created_at", sa.DateTime),
    )
    role_permissions = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for code, description in PERMISSIONS:
        permission_id = bind.execute(
            sa.select(permissions.c.id).where(permissions.c.code == code)
        ).scalar_one_or_none()
        if permission_id is None:
            bind.execute(
                permissions.insert().values(
                    code=code,
                    description=description,
                )
            )

    for name, rank, description, permission_codes in ROLES:
        role_id = bind.execute(
            sa.select(roles.c.id).where(roles.c.name == name)
        ).scalar_one_or_none()
        if role_id is None:
            bind.execute(
                roles.insert().values(
                    name=name,
                    rank=rank,
                    description=description,
                    created_at=now,
                )
            )
            role_id = bind.execute(
                sa.select(roles.c.id).where(roles.c.name == name)
            ).scalar_one()
        else:
            bind.execute(
                roles.update()
                .where(roles.c.id == role_id)
                .values(rank=rank, description=description)
            )

        for code in permission_codes:
            permission_id = bind.execute(
                sa.select(permissions.c.id).where(permissions.c.code == code)
            ).scalar_one()
            exists = bind.execute(
                sa.select(role_permissions.c.role_id).where(
                    role_permissions.c.role_id == role_id,
                    role_permissions.c.permission_id == permission_id,
                )
            ).scalar_one_or_none()
            if exists is None:
                bind.execute(
                    role_permissions.insert().values(
                        role_id=role_id,
                        permission_id=permission_id,
                    )
                )


def downgrade():
    bind = op.get_bind()
    permissions = sa.table(
        "permissions",
        sa.column("id", sa.Integer),
        sa.column("code", sa.String),
    )
    roles = sa.table(
        "roles",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
    )
    role_permissions = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )

    role_names = [role[0] for role in ROLES]
    permission_codes = [permission[0] for permission in PERMISSIONS]
    role_ids = [
        row[0]
        for row in bind.execute(
            sa.select(roles.c.id).where(roles.c.name.in_(role_names))
        )
    ]
    if role_ids:
        bind.execute(
            role_permissions.delete().where(
                role_permissions.c.role_id.in_(role_ids)
            )
        )
    bind.execute(roles.delete().where(roles.c.name.in_(role_names)))
    bind.execute(permissions.delete().where(permissions.c.code.in_(permission_codes)))
