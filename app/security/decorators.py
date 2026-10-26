"""Server-side authorisation decorators."""

from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import abort
from flask_login import current_user

from app.extensions import login_manager


def permission_required(*permissions: str) -> Callable:
    """Require every listed permission, enforced before the view executes."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if not all(current_user.has_permission(code) for code in permissions):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
