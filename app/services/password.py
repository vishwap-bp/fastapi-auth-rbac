"""
services/password.py — Password hashing, verification, and change/reset flows.

Uses bcrypt directly (no passlib). passlib is unmaintained and incompatible
with bcrypt>=4.x. Direct bcrypt usage is simpler and works on all versions.
"""

from __future__ import annotations

import bcrypt
from sqlalchemy.orm import Session

from app.models.user import User


def hash_password(plain: str) -> str:
    """Hash a plaintext password. Returns bcrypt hash string."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def change_password(
    db: Session,
    user: User,
    current_password: str,
    new_password: str,
) -> None:
    """
    Change password for a logged-in user who knows their current password.

    Raises ValueError if:
      - User has no password (OAuth-only account)
      - Current password is incorrect
      - New password is the same as current
    """
    if not user.hashed_password:
        raise ValueError("This account uses social login. Set a password via forgot-password first.")

    if not verify_password(current_password, user.hashed_password):
        raise ValueError("Current password is incorrect.")

    if verify_password(new_password, user.hashed_password):
        raise ValueError("New password must be different from the current password.")

    user.hashed_password = hash_password(new_password)
    db.flush()


def set_new_password(db: Session, user: User, new_password: str) -> None:
    """
    Directly set a new password (used after a verified reset token).
    No current password required.
    """
    user.hashed_password = hash_password(new_password)
    db.flush()
