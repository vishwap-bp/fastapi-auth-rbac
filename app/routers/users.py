"""
routers/users.py — User profile and admin user management endpoints.

Endpoints:
  GET   /users/me              My profile (any authenticated user)
  PATCH /users/me              Update my profile
  GET   /users                 List all users (admin only)
  GET   /users/{user_id}       Get a specific user (admin only)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_current_active_user, require_admin
from app.models.user import User
from app.schemas.user import UserAdminRead, UserRead, UserUpdate
from app.schemas.core import ApiResponse

router = APIRouter()


@router.get("/me", response_model=ApiResponse[UserRead])
def get_my_profile(current_user: User = Depends(get_current_active_user)):
    """Return the current authenticated user's profile."""
    return ApiResponse(status=True, statusCode=200, message="Success", data=current_user)


@router.patch("/me", response_model=ApiResponse[UserRead])
def update_my_profile(
    body: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update the current user's profile fields."""
    if body.email and body.email != current_user.email:
        existing = db.query(User).filter(User.email == body.email).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use.",
            )
        current_user.email = body.email
        current_user.is_verified = False  # Re-verify on email change

    db.commit()
    db.refresh(current_user)
    return ApiResponse(status=True, statusCode=200, message="Success", data=current_user)


@router.get("", response_model=ApiResponse[list[UserAdminRead]])
def list_users(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """List all users. Admin only."""
    users = db.query(User).offset(skip).limit(limit).all()
    return ApiResponse(status=True, statusCode=200, message="Success", data=users)


@router.get("/{user_id}", response_model=ApiResponse[UserAdminRead])
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Get a specific user by ID. Admin only."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return ApiResponse(status=True, statusCode=200, message="Success", data=user)
