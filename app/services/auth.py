"""
services/auth.py — Core authentication business logic.

Handles: registration, login (with lockout), logout, token refresh delegation,
password reset flow, email verification flow, and Google OAuth sign-in.

All token DB operations (create, rotate, revoke) are delegated to services/token.py.
Audit logging is done inline via services/audit.py within the same transaction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import User
from app.services import audit as audit_svc
from app.services.email import send_email
from app.services.password import hash_password, set_new_password, verify_password
from app.services import token as token_svc


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------

def register_user(
    db: Session,
    email: str,
    password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> User:
    """
    Register a new user with email + password.

    Raises HTTPException(409) if email already exists.
    Sends an email verification email after creating the account.
    """
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        email=email,
        hashed_password=hash_password(password),
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    db.flush()  # Get user.id without committing

    # Write audit log in same transaction
    audit_svc.log_event(
        db=db,
        action=audit_svc.USER_REGISTERED,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.commit()
    db.refresh(user)

    # Send verification email (outside transaction — email failure should not roll back registration)
    _send_verification_email(user.email)

    return user


def _send_verification_email(email: str) -> None:
    verification_token = token_svc.make_email_verification_token(email)
    link = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"
    send_email(
        to=email,
        subject="Verify your email address",
        html_body=(
            f"<p>Welcome! Please verify your email address by clicking the link below.</p>"
            f'<p><a href="{link}">Verify Email</a></p>'
            f"<p>This link expires in 24 hours.</p>"
            f"<p>If you did not create an account, ignore this email.</p>"
        ),
    )


# ------------------------------------------------------------------
# Email verification
# ------------------------------------------------------------------

def verify_email(
    db: Session,
    token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> User:
    """
    Confirm email verification token and mark user as verified.
    Raises HTTPException(400) on invalid/expired token or if already verified.
    """
    try:
        email = token_svc.verify_email_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified.",
        )

    user.is_verified = True
    audit_svc.log_event(
        db=db, action=audit_svc.EMAIL_VERIFIED,
        user_id=user.id, ip_address=ip_address, user_agent=user_agent,
    )
    db.commit()
    db.refresh(user)
    return user


# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------

def login_user(
    db: Session,
    email: str,
    password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> tuple[str, str]:
    """
    Authenticate a user with email + password.

    Returns (access_token, refresh_token) on success.
    Raises HTTPException(401/423) on failure.
    Enforces account lockout after MAX_LOGIN_ATTEMPTS failures.
    """
    user = db.query(User).filter(User.email == email).first()

    # --- Lockout check (done before password verification to prevent timing attacks) ---
    if user and user.locked_until:
        locked_until_utc = user.locked_until.replace(tzinfo=timezone.utc)
        if locked_until_utc > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account is locked until {user.locked_until.isoformat()}. Try again later.",
            )
        else:
            # Lock period expired — reset
            user.failed_login_attempts = 0
            user.locked_until = None

    # --- User existence + password check ---
    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=settings.LOCKOUT_DURATION_MINUTES
                )
                audit_svc.log_event(
                    db=db, action=audit_svc.ACCOUNT_LOCKED,
                    user_id=user.id, ip_address=ip_address, user_agent=user_agent,
                    details={"attempts": user.failed_login_attempts},
                )
            audit_svc.log_event(
                db=db, action=audit_svc.LOGIN_FAILURE,
                user_id=user.id, ip_address=ip_address, user_agent=user_agent,
            )
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled.",
        )

    # --- Success: reset failed attempts, issue tokens ---
    user.failed_login_attempts = 0
    user.locked_until = None

    refresh_str, db_token = token_svc.create_refresh_token(
        db=db, user=user, ip_address=ip_address, user_agent=user_agent,
    )
    roles = [r.name for r in user.roles]
    permissions = list({p.code for r in user.roles for p in r.permissions})
    access_str = token_svc.create_access_token(
        user_id=user.id,
        refresh_jti=db_token.jti,
        roles=roles,
        permissions=permissions,
    )

    audit_svc.log_event(
        db=db, action=audit_svc.LOGIN_SUCCESS,
        user_id=user.id, ip_address=ip_address, user_agent=user_agent,
    )
    db.commit()
    return access_str, refresh_str


# ------------------------------------------------------------------
# Logout
# ------------------------------------------------------------------

def logout_user(
    db: Session,
    refresh_token_str: str,
    user_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Revoke the provided refresh token, ending the current session."""
    from jose import JWTError, jwt
    try:
        payload = jwt.decode(refresh_token_str, settings.SECRET_KEY, algorithms=["HS256"])
        jti = payload.get("jti")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token.")

    if jti:
        token_svc.revoke_token(db, jti)

    audit_svc.log_event(
        db=db, action=audit_svc.LOGOUT,
        user_id=user_id, ip_address=ip_address, user_agent=user_agent,
    )
    db.commit()


# ------------------------------------------------------------------
# Forgot / Reset Password
# ------------------------------------------------------------------

def forgot_password(
    db: Session,
    email: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """
    Send a password reset email.
    Always returns success even if email not found (prevents user enumeration).
    """
    user = db.query(User).filter(User.email == email).first()
    if user:
        audit_svc.log_event(
            db=db, action=audit_svc.PASSWORD_RESET_REQ,
            user_id=user.id, ip_address=ip_address, user_agent=user_agent,
        )
        db.commit()

        reset_token = token_svc.make_password_reset_token(email)
        link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        send_email(
            to=email,
            subject="Reset your password",
            html_body=(
                f"<p>We received a request to reset your password.</p>"
                f'<p><a href="{link}">Reset Password</a></p>'
                f"<p>This link expires in 1 hour.</p>"
                f"<p>If you did not request this, you can safely ignore this email.</p>"
            ),
        )


def reset_password(
    db: Session,
    token: str,
    new_password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """
    Verify reset token and set new password.
    Also revokes all existing refresh tokens for the user (security: all sessions invalidated).
    """
    try:
        email = token_svc.verify_password_reset_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    set_new_password(db, user, new_password)
    token_svc.revoke_all_user_tokens(db, user.id)

    audit_svc.log_event(
        db=db, action=audit_svc.PASSWORD_RESET_DONE,
        user_id=user.id, ip_address=ip_address, user_agent=user_agent,
    )
    db.commit()


# ------------------------------------------------------------------
# Google OAuth Sign-In / Sign-Up
# ------------------------------------------------------------------

def google_oauth_login(
    db: Session,
    id_token_str: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> tuple[str, str]:
    """
    Verify Google id_token, find or create user, issue access + refresh tokens.

    Returns (access_token, refresh_token).
    Raises HTTPException(503) if Google OAuth is not configured.
    """
    from app.services.oauth import verify_google_token

    google_info = verify_google_token(id_token_str)

    # Find by google_id first, then by email (handles migration of existing accounts)
    user = db.query(User).filter(User.google_id == google_info.google_id).first()
    if not user:
        user = db.query(User).filter(User.email == google_info.email).first()

    if user:
        # Link google_id to existing account if not already linked
        if not user.google_id:
            user.google_id = google_info.google_id
            user.oauth_provider = "google"
    else:
        # Create new account
        user = User(
            email=google_info.email,
            google_id=google_info.google_id,
            oauth_provider="google",
            is_active=True,
            is_verified=google_info.email_verified,
            hashed_password=None,
        )
        db.add(user)
        db.flush()

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled.")

    refresh_str, db_token = token_svc.create_refresh_token(
        db=db, user=user, ip_address=ip_address, user_agent=user_agent,
    )
    roles = [r.name for r in user.roles]
    permissions = list({p.code for r in user.roles for p in r.permissions})
    access_str = token_svc.create_access_token(
        user_id=user.id,
        refresh_jti=db_token.jti,
        roles=roles,
        permissions=permissions,
    )

    audit_svc.log_event(
        db=db, action=audit_svc.GOOGLE_LOGIN,
        user_id=user.id, ip_address=ip_address, user_agent=user_agent,
    )
    db.commit()
    return access_str, refresh_str
