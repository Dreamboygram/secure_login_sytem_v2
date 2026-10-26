"""Import all models so Alembic and the application see one metadata graph."""

from app.models.record import UserRecord
from app.models.roles import Permission, Role, role_permissions
from app.models.security import (
    AppSetting,
    AuditLog,
    LoginAttempt,
    PasswordReset,
    RecoveryCode,
)
from app.models.user import User

__all__ = [
    "AppSetting",
    "AuditLog",
    "LoginAttempt",
    "PasswordReset",
    "Permission",
    "RecoveryCode",
    "Role",
    "User",
    "UserRecord",
    "role_permissions",
]
