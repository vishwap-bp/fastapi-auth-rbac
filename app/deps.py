"""
deps.py — Shared FastAPI dependency functions.

RULE (Architecture Rule 2):
  get_current_user() decodes the access token and fetches the user.
  It does NOT update last_used_at on the refresh token — that only
  happens in services/token.py at login and refresh time.

Usage in routes:
    from app.deps import get_current_user, require_role, require_permission

    @router.get("/admin", dependencies=[Depends(require_role("admin"))])
    def admin_only(): ...

    @router.get("/reports", dependencies=[Depends(require_permission("reports:read"))])
    def reports(): ...
"""

from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services.token import decode_access_token

_bearer = HTTPBearer(auto_error=True)


def get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP, respecting X-Forwarded-For for reverse proxies."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    Decode the Bearer access token and return the authenticated User.

    RULE 2: Does NOT update last_used_at — that only happens in
    services/token.py at login and refresh.

    Raises HTTPException(401) on invalid/expired token.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise credentials_exc

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise credentials_exc
    return user


def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Ensure the authenticated user is active (not disabled)."""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled.",
        )
    return user


def require_role(role_name: str):
    """
    Dependency factory: raise 403 if user does not have the required role.
    Superusers bypass all role checks.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
    """
    def checker(user: User = Depends(get_current_active_user)) -> User:
        if user.is_superuser:
            return user
        user_role_names = {r.name for r in user.roles}
        if role_name not in user_role_names:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role_name}' is required.",
            )
        return user
    return checker


def require_permission(permission_code: str):
    """
    Dependency factory: raise 403 if user does not have the required permission.
    Superusers bypass all permission checks.

    Usage:
        @router.get("/reports", dependencies=[Depends(require_permission("reports:read"))])
    """
    def checker(user: User = Depends(get_current_active_user)) -> User:
        if user.is_superuser:
            return user
        user_permissions = {p.code for r in user.roles for p in r.permissions}
        if permission_code not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission_code}' is required.",
            )
        return user
    return checker


def require_admin(user: User = Depends(get_current_active_user)) -> User:
    """Shorthand dependency: require superuser or 'admin' role."""
    if user.is_superuser:
        return user
    user_role_names = {r.name for r in user.roles}
    if "admin" not in user_role_names:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return user
