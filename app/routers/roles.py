"""
routers/roles.py — Role and Permission management endpoints. Admin only.

Endpoints:
  GET    /roles                              List all roles
  POST   /roles                              Create a role
  GET    /roles/permissions                  List all permissions
  POST   /roles/permissions                  Create a permission
  POST   /roles/{role_id}/permissions        Add permission to role
  DELETE /roles/{role_id}/permissions/{id}   Remove permission from role
  POST   /users/{user_id}/roles              Assign role to user
  DELETE /users/{user_id}/roles/{role_id}    Remove role from user
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_client_ip, get_current_active_user, require_admin
from app.models.role import Permission, Role
from app.models.user import User
from app.schemas.role import (
    AssignPermissionRequest,
    AssignRoleRequest,
    PermissionCreate,
    PermissionRead,
    RoleCreate,
    RoleRead,
)
from app.schemas.core import ApiResponse
from app.utils.response import success_response
from app.services import audit as audit_svc

router = APIRouter()


# ------------------------------------------------------------------
# Roles
# ------------------------------------------------------------------

@router.get("", response_model=ApiResponse[list[RoleRead]])
def list_roles(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """List all roles with their permissions. Admin only."""
    roles = db.query(Role).all()
    return ApiResponse(status=True, statusCode=200, message="Success", data=roles)


@router.post("", response_model=ApiResponse[RoleRead], status_code=status.HTTP_201_CREATED)
def create_role(
    body: RoleCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Create a new role. Admin only."""
    if db.query(Role).filter(Role.name == body.name).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role '{body.name}' already exists.",
        )
    role = Role(name=body.name, description=body.description)
    db.add(role)
    db.commit()
    db.refresh(role)
    return ApiResponse(status=True, statusCode=201, message="Success", data=role)


# ------------------------------------------------------------------
# Permissions
# ------------------------------------------------------------------

@router.get("/permissions", response_model=ApiResponse[list[PermissionRead]])
def list_permissions(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """List all permissions. Admin only."""
    perms = db.query(Permission).all()
    return ApiResponse(status=True, statusCode=200, message="Success", data=perms)


@router.post("/permissions", response_model=ApiResponse[PermissionRead], status_code=status.HTTP_201_CREATED)
def create_permission(
    body: PermissionCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Create a new permission. Admin only."""
    if db.query(Permission).filter(Permission.code == body.code).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Permission '{body.code}' already exists.",
        )
    perm = Permission(code=body.code, description=body.description)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return ApiResponse(status=True, statusCode=201, message="Success", data=perm)


# ------------------------------------------------------------------
# Role ↔ Permission assignment
# ------------------------------------------------------------------

@router.post("/{role_id}/permissions", response_model=ApiResponse[RoleRead])
def add_permission_to_role(
    role_id: int,
    body: AssignPermissionRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Add a permission to a role. Admin only."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    perm = db.query(Permission).filter(Permission.id == body.permission_id).first()
    if not perm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found.")

    if perm not in role.permissions:
        role.permissions.append(perm)
        audit_svc.log_event(
            db=db, action=audit_svc.PERMISSION_ASSIGNED,
            user_id=admin.id, ip_address=get_client_ip(request),
            details={"role_id": role_id, "permission_code": perm.code},
        )
        db.commit()
        db.refresh(role)

    return ApiResponse(status=True, statusCode=200, message="Success", data=role)


@router.delete("/{role_id}/permissions/{permission_id}", response_model=ApiResponse[RoleRead])
def remove_permission_from_role(
    role_id: int,
    permission_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Remove a permission from a role. Admin only."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm or perm not in role.permissions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found on this role.",
        )

    role.permissions.remove(perm)
    audit_svc.log_event(
        db=db, action=audit_svc.PERMISSION_REMOVED,
        user_id=admin.id, ip_address=get_client_ip(request),
        details={"role_id": role_id, "permission_code": perm.code},
    )
    db.commit()
    db.refresh(role)
    return ApiResponse(status=True, statusCode=200, message="Success", data=role)


# ------------------------------------------------------------------
# User ↔ Role assignment
# ------------------------------------------------------------------

@router.post("/users/{user_id}/roles", status_code=status.HTTP_200_OK)
def assign_role_to_user(
    user_id: int,
    body: AssignRoleRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Assign a role to a user. Admin only."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    role = db.query(Role).filter(Role.id == body.role_id).first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    if role not in user.roles:
        user.roles.append(role)
        audit_svc.log_event(
            db=db, action=audit_svc.ROLE_ASSIGNED,
            user_id=admin.id, ip_address=get_client_ip(request),
            details={"target_user_id": user_id, "role_name": role.name},
        )
        db.commit()

    return success_response(message=f"Role '{role.name}' assigned to user {user_id}.")


@router.delete("/users/{user_id}/roles/{role_id}")
def remove_role_from_user(
    user_id: int,
    role_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Remove a role from a user. Admin only."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    role = db.query(Role).filter(Role.id == role_id).first()
    if not role or role not in user.roles:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found on this user.",
        )

    user.roles.remove(role)
    audit_svc.log_event(
        db=db, action=audit_svc.ROLE_REMOVED,
        user_id=admin.id, ip_address=get_client_ip(request),
        details={"target_user_id": user_id, "role_name": role.name},
    )
    db.commit()
    return success_response(message=f"Role '{role.name}' removed from user {user_id}.")
