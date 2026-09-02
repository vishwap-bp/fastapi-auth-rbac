"""
schemas/role.py — Role and Permission request/response shapes.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class PermissionCreate(BaseModel):
    code: str
    description: Optional[str] = None


class PermissionRead(BaseModel):
    id: int
    code: str
    description: Optional[str]

    model_config = {"from_attributes": True}


class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None


class RoleRead(BaseModel):
    id: int
    name: str
    description: Optional[str]
    permissions: list[PermissionRead] = []

    model_config = {"from_attributes": True}


class AssignRoleRequest(BaseModel):
    role_id: int


class AssignPermissionRequest(BaseModel):
    permission_id: int
