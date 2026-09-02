"""
routers/auth.py — All authentication endpoints.

Endpoints:
  POST /auth/register           Signup
  POST /auth/login              Login → access + refresh token
  POST /auth/logout             Revoke current refresh token
  POST /auth/refresh            Rotate refresh token
  POST /auth/verify-email       Confirm email with signed token
  POST /auth/forgot-password    Request password reset email
  POST /auth/reset-password     Set new password with reset token
  POST /auth/change-password    Change password (authenticated)
  POST /auth/oauth/google       Google Sign-In
  GET  /auth/sessions           List active sessions
  DELETE /auth/sessions/{id}   Revoke one session
  DELETE /auth/sessions         Revoke all other sessions
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import get_client_ip, get_current_active_user, get_current_user
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    GoogleOAuthRequest,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,
)
from app.schemas.session import SessionRead
from app.schemas.core import ApiResponse
from app.services import auth as auth_svc
from app.services import audit as audit_svc
from app.services import token as token_svc
from app.services.password import change_password

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

_RATE_LIMIT = "5/minute"  # Applied on sensitive endpoints


# ------------------------------------------------------------------
# Register
# ------------------------------------------------------------------

@router.post("/register", response_model=ApiResponse[None], status_code=status.HTTP_201_CREATED)
@limiter.limit(_RATE_LIMIT)
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
    """Sign up with email and password. Sends a verification email."""
    auth_svc.register_user(
        db=db,
        email=body.email,
        password=body.password,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return ApiResponse(status=True, statusCode=201, message="Account created. Please check your email to verify your account.")


# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------

@router.post("/login", response_model=ApiResponse[LoginResponse])
@limiter.limit(_RATE_LIMIT)
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate and receive access + refresh tokens."""
    access_token, refresh_token = auth_svc.login_user(
        db=db,
        email=body.email,
        password=body.password,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    data = LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return ApiResponse(status=True, statusCode=200, message="Success", data=data)


# ------------------------------------------------------------------
# Logout
# ------------------------------------------------------------------

@router.post("/logout", response_model=ApiResponse[None])
def logout(
    body: LogoutRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Revoke the current session's refresh token."""
    auth_svc.logout_user(
        db=db,
        refresh_token_str=body.refresh_token,
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return ApiResponse(status=True, statusCode=200, message="Logged out successfully.")


# ------------------------------------------------------------------
# Token Refresh
# ------------------------------------------------------------------

@router.post("/refresh", response_model=ApiResponse[RefreshResponse])
def refresh(body: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    """
    Exchange a refresh token for a new access + refresh token pair.
    The old refresh token is immediately revoked.
    """
    try:
        new_access, new_refresh, _ = token_svc.rotate_refresh_token(
            db=db,
            refresh_token_str=body.refresh_token,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    audit_svc.log_event(db=db, action=audit_svc.TOKEN_REFRESH)
    db.commit()

    data = RefreshResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return ApiResponse(status=True, statusCode=200, message="Success", data=data)


# ------------------------------------------------------------------
# Email Verification
# ------------------------------------------------------------------

@router.post("/verify-email", response_model=ApiResponse[None])
def verify_email(body: VerifyEmailRequest, request: Request, db: Session = Depends(get_db)):
    """Confirm email address using the signed token sent during registration."""
    auth_svc.verify_email(
        db=db,
        token=body.token,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return ApiResponse(status=True, statusCode=200, message="Email verified successfully.")


# ------------------------------------------------------------------
# Forgot Password
# ------------------------------------------------------------------

@router.post("/forgot-password", response_model=ApiResponse[None])
@limiter.limit(_RATE_LIMIT)
def forgot_password(request: Request, body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Request a password reset email.
    Always returns success to prevent user enumeration.
    """
    auth_svc.forgot_password(
        db=db,
        email=body.email,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return ApiResponse(status=True, statusCode=200, message="If an account exists with that email, a reset link has been sent.")


# ------------------------------------------------------------------
# Reset Password
# ------------------------------------------------------------------

@router.post("/reset-password", response_model=ApiResponse[None])
def reset_password(body: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Set a new password using the signed token from the reset email."""
    auth_svc.reset_password(
        db=db,
        token=body.token,
        new_password=body.new_password,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return ApiResponse(status=True, statusCode=200, message="Password reset successfully. All sessions have been invalidated.")


# ------------------------------------------------------------------
# Change Password (authenticated)
# ------------------------------------------------------------------

@router.post("/change-password", response_model=ApiResponse[None])
def change_password_endpoint(
    body: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Change password for a logged-in user. Requires current password."""
    try:
        change_password(
            db=db,
            user=current_user,
            current_password=body.current_password,
            new_password=body.new_password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    audit_svc.log_event(
        db=db,
        action=audit_svc.PASSWORD_CHANGED,
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    db.commit()
    return ApiResponse(status=True, statusCode=200, message="Password changed successfully.")


# ------------------------------------------------------------------
# Google OAuth Sign-In
# ------------------------------------------------------------------

@router.post("/oauth/google", response_model=ApiResponse[LoginResponse])
def google_oauth(body: GoogleOAuthRequest, request: Request, db: Session = Depends(get_db)):
    """
    Sign in with Google.
    Disabled (503) if GOOGLE_CLIENT_ID is not set in .env.
    """
    access_token, refresh_token = auth_svc.google_oauth_login(
        db=db,
        id_token_str=body.id_token,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    data = LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return ApiResponse(status=True, statusCode=200, message="Success", data=data)


# ------------------------------------------------------------------
# Session Management
# ------------------------------------------------------------------

@router.get("/sessions", response_model=ApiResponse[list[SessionRead]])
def list_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List all active sessions (refresh tokens) for the current user."""
    sessions = token_svc.get_active_sessions(db, current_user.id)
    return ApiResponse(status=True, statusCode=200, message="Success", data=sessions)


@router.delete("/sessions", response_model=ApiResponse[None])
def revoke_all_other_sessions(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Revoke all sessions except the current one.
    Current session is identified via refresh_jti embedded in the access token.
    """
    from jose import jwt as jose_jwt
    auth_header = request.headers.get("Authorization", "")
    current_refresh_jti: str | None = None
    if auth_header.startswith("Bearer "):
        try:
            payload = jose_jwt.decode(
                auth_header[7:], settings.SECRET_KEY, algorithms=["HS256"]
            )
            current_refresh_jti = payload.get("refresh_jti")
        except Exception:
            pass

    count = token_svc.revoke_all_user_tokens(
        db=db, user_id=current_user.id, exclude_jti=current_refresh_jti
    )
    audit_svc.log_event(
        db=db,
        action=audit_svc.TOKEN_REVOKED,
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        details={"revoked_count": count, "scope": "all_other_sessions"},
    )
    db.commit()
    return ApiResponse(status=True, statusCode=200, message=f"{count} other session(s) revoked.")


@router.delete("/sessions/{session_id}", response_model=ApiResponse[None])
def revoke_session(
    session_id: int,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Revoke a specific session by its ID."""
    from app.models.token import RefreshToken

    token = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.id == session_id,
            RefreshToken.user_id == current_user.id,
        )
        .first()
    )
    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    token.is_revoked = True
    audit_svc.log_event(
        db=db,
        action=audit_svc.TOKEN_REVOKED,
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        details={"session_id": session_id},
    )
    db.commit()
    return ApiResponse(status=True, statusCode=200, message="Session revoked.")
