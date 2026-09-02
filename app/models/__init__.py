"""
models/__init__.py

Import all models here so SQLAlchemy's Base.metadata is aware of every
table before Alembic generates migrations or create_all() is called.
"""

from app.models.audit import AuditLog
from app.models.role import Permission, Role, role_permissions
from app.models.token import RefreshToken
from app.models.user import User, user_roles

__all__ = [
    "User",
    "user_roles",
    "Role",
    "Permission",
    "role_permissions",
    "RefreshToken",
    "AuditLog",
]
