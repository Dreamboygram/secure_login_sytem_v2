"""Central role and permission definitions.

The server derives every authorisation decision from this matrix. Templates
may hide links for usability, but hidden controls are never the enforcement
mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

PERMISSIONS: Final[dict[str, str]] = {
    "dashboard.view": "Access the authenticated dashboard.",
    "account.security": "Manage own password and two-factor settings.",
    "records.view_own": "View own operational records.",
    "records.manage_own": "Create and update own operational records.",
    "records.moderate": "View and moderate operational records.",
    "admin.view": "Access the administrative dashboard.",
    "users.view": "View the user directory.",
    "users.manage": "Create, deactivate, and manage user accounts.",
    "roles.assign": "Assign permitted roles to users.",
    "audit.view": "Review security audit activity.",
    "security.manage": "Perform controlled security recovery actions.",
    "manager.view": "Access the management dashboard.",
    "reports.view": "View authorised operational reports.",
}


@dataclass(frozen=True)
class RoleDefinition:
    name: str
    rank: int
    description: str
    permissions: tuple[str, ...]


ROLE_DEFINITIONS: Final[dict[str, RoleDefinition]] = {
    "INPUTER": RoleDefinition(
        name="INPUTER",
        rank=10,
        description="Operational data entry and own-record management.",
        permissions=(
            "dashboard.view",
            "account.security",
            "records.view_own",
            "records.manage_own",
        ),
    ),
    "MANAGER": RoleDefinition(
        name="MANAGER",
        rank=40,
        description="Management reporting and operational oversight.",
        permissions=(
            "dashboard.view",
            "account.security",
            "manager.view",
            "reports.view",
        ),
    ),
    "ADMIN": RoleDefinition(
        name="ADMIN",
        rank=60,
        description="Administrative oversight without account administration.",
        permissions=(
            "dashboard.view",
            "account.security",
            "admin.view",
            "users.view",
            "audit.view",
            "records.moderate",
        ),
    ),
    "ADMINISTRATOR": RoleDefinition(
        name="ADMINISTRATOR",
        rank=100,
        description="Full account, role, and security administration.",
        permissions=(
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
}

ROLE_RANKS: Final[dict[str, int]] = {
    name: definition.rank for name, definition in ROLE_DEFINITIONS.items()
}
PRIVILEGED_ROLES: Final[frozenset[str]] = frozenset(
    {"MANAGER", "ADMIN", "ADMINISTRATOR"}
)
VALID_ROLE_NAMES: Final[tuple[str, ...]] = tuple(ROLE_DEFINITIONS)


def role_has_permission(role_name: str | None, permission: str) -> bool:
    definition = ROLE_DEFINITIONS.get(role_name or "")
    return bool(definition and permission in definition.permissions)


def role_is_privileged(role_name: str | None) -> bool:
    return role_name in PRIVILEGED_ROLES


def assignable_role_names(actor_rank: int) -> tuple[str, ...]:
    """Roles at or below the actor's rank, in ascending privilege order."""
    return tuple(
        name
        for name, definition in sorted(
            ROLE_DEFINITIONS.items(), key=lambda item: item[1].rank
        )
        if definition.rank <= actor_rank
    )
