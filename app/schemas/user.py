"""
schemas/user.py — User read and update shapes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class RoleBasic(BaseModel):
    id: int
    name: str

    model_config = {"from_attributes": True}


class UserRead(BaseModel):
    id: int
    email: EmailStr
    is_active: bool
    is_verified: bool
    is_superuser: bool
    oauth_provider: Optional[str]
    created_at: datetime
    roles: list[RoleBasic] = []

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None


class UserAdminRead(UserRead):
    """Extended user view available to admin endpoints only."""
    failed_login_attempts: int
    locked_until: Optional[datetime]
    updated_at: Optional[datetime]

    model_config = {"from_attributes": True}
