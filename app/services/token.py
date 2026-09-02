"""
services/token.py — JWT creation/verification and refresh token lifecycle.

ARCHITECTURE RULE 2 (enforced here):
  last_used_at is updated ONLY in this file, at two points:
    1. create_refresh_token() — on login (new token created)
    2. rotate_refresh_token() — on refresh (new token issued)
  It is NEVER updated in deps.py on access-token validation.

Refresh token security model:
  - Every refresh token has a unique jti (UUID) and a family_id (UUID).
  - family_id is shared across all tokens in one refresh chain
    (first token and all rotations share the same family_id).
  - On rotate_refresh_token():
      1. Look up token by jti.
      2. If revoked → REPLAY ATTACK detected → revoke entire family → raise error.
      3. If expired or not found → raise error.
      4. Mark old token as revoked.
      5. Create new token with same family_id.
      6. Update last_used_at on NEW token (Rule 2).
  - On logout: revoke by jti only.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.models.token import RefreshToken
from app.models.user import User

ALGORITHM = "HS256"


# ------------------------------------------------------------------
# Access token
# ------------------------------------------------------------------

def create_access_token(
    user_id: int,
    refresh_jti: str,
    roles: list[str],
    permissions: list[str],
) -> str:
    """
    Issue a short-lived JWT access token.

    Includes refresh_jti so DELETE /auth/sessions can identify the
    current session to exclude during "revoke all others".
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(user_id),
        "jti": str(uuid.uuid4()),
        "refresh_jti": refresh_jti,  # links access token to its refresh token
        "roles": roles,
        "permissions": permissions,
        "exp": expire,
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate an access token. Raises JWTError on failure."""
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    if payload.get("type") != "access":
        raise JWTError("Invalid token type.")
    return payload


# ------------------------------------------------------------------
# Refresh token
# ------------------------------------------------------------------

def _get_user_roles_and_permissions(user: User) -> tuple[list[str], list[str]]:
    """Extract role names and permission codes from a User's loaded relationships."""
    roles = [r.name for r in user.roles]
    permissions = list({p.code for r in user.roles for p in r.permissions})
    return roles, permissions


def create_refresh_token(
    db: Session,
    user: User,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    family_id: Optional[str] = None,
) -> tuple[str, RefreshToken]:
    """
    Create and persist a new refresh token for a user.

    RULE 2: Sets last_used_at here (login point). This is one of only
    two places in the codebase where last_used_at is written.

    Returns (encoded_jwt_string, RefreshToken ORM object).
    """
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    fid = family_id or str(uuid.uuid4())
    expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "jti": jti,
        "family_id": fid,
        "exp": expires_at,
        "type": "refresh",
    }
    token_str = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

    db_token = RefreshToken(
        jti=jti,
        family_id=fid,
        user_id=user.id,
        is_revoked=False,
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent,
        last_used_at=now,  # RULE 2 — set on login
    )
    db.add(db_token)
    db.flush()
    return token_str, db_token


def rotate_refresh_token(
    db: Session,
    refresh_token_str: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> tuple[str, str, RefreshToken]:
    """
    Validate old refresh token, revoke it, and issue a new one.

    RULE 2: Sets last_used_at on the NEW token (refresh point). This is
    the second and only other place where last_used_at is written.

    Replay attack: If a revoked token is presented, the entire token family
    is revoked immediately as a compromise response.

    Returns (new_access_token, new_refresh_token_str, new_db_token).
    Raises ValueError on any validation failure.
    """
    # 1. Decode the JWT
    try:
        payload = jwt.decode(refresh_token_str, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise ValueError(f"Invalid refresh token: {exc}") from exc

    if payload.get("type") != "refresh":
        raise ValueError("Invalid token type.")

    jti = payload["jti"]
    family_id = payload["family_id"]

    # 2. Look up in DB
    db_token = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()
    if not db_token:
        raise ValueError("Refresh token not found.")

    # 3. Replay attack detection
    if db_token.is_revoked:
        # Revoke entire family immediately
        db.query(RefreshToken).filter(
            RefreshToken.family_id == family_id,
            RefreshToken.is_revoked == False,  # noqa: E712
        ).update({"is_revoked": True})
        db.commit()
        raise ValueError("Refresh token already used. All sessions in this chain have been revoked.")

    # 4. Expiry check
    now = datetime.now(timezone.utc)
    if db_token.expires_at.replace(tzinfo=timezone.utc) < now:
        raise ValueError("Refresh token has expired.")

    # 5. Revoke old token
    db_token.is_revoked = True
    db.flush()

    # 6. Load user with roles
    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user or not user.is_active:
        raise ValueError("User not found or inactive.")

    # 7. Issue new token (same family_id) — RULE 2: last_used_at set in create_refresh_token
    new_refresh_str, new_db_token = create_refresh_token(
        db=db,
        user=user,
        ip_address=ip_address,
        user_agent=user_agent,
        family_id=family_id,  # keep same family
    )

    # 8. Issue new access token
    roles, permissions = _get_user_roles_and_permissions(user)
    new_access_str = create_access_token(
        user_id=user.id,
        refresh_jti=new_db_token.jti,
        roles=roles,
        permissions=permissions,
    )

    return new_access_str, new_refresh_str, new_db_token


def revoke_token(db: Session, jti: str) -> bool:
    """Revoke a single refresh token by jti. Returns True if found, False otherwise."""
    token = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()
    if not token:
        return False
    token.is_revoked = True
    db.flush()
    return True


def revoke_all_user_tokens(db: Session, user_id: int, exclude_jti: Optional[str] = None) -> int:
    """
    Revoke all active refresh tokens for a user.
    Optionally exclude one jti (used for 'logout all other sessions').
    Returns count of revoked tokens.
    """
    query = db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked == False,  # noqa: E712
    )
    if exclude_jti:
        query = query.filter(RefreshToken.jti != exclude_jti)
    count = query.update({"is_revoked": True})
    db.flush()
    return count


def get_active_sessions(db: Session, user_id: int) -> list[RefreshToken]:
    """Return all non-revoked, non-expired refresh tokens for a user."""
    now = datetime.now(timezone.utc)
    return (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False,  # noqa: E712
            RefreshToken.expires_at > now,
        )
        .order_by(RefreshToken.created_at.desc())
        .all()
    )


# ------------------------------------------------------------------
# Signed tokens for email verification and password reset
# (itsdangerous — URL-safe, time-limited, signed with SECRET_KEY)
# ------------------------------------------------------------------

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


def _signer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.SECRET_KEY)


def make_email_verification_token(email: str) -> str:
    """Generate a signed, time-limited email verification token."""
    return _signer().dumps(email, salt="email-verify")


def verify_email_token(token: str, max_age_seconds: int = 86400) -> str:
    """
    Validate an email verification token.
    Returns the email address or raises ValueError.
    Default expiry: 24 hours.
    """
    try:
        return _signer().loads(token, salt="email-verify", max_age=max_age_seconds)
    except SignatureExpired:
        raise ValueError("Email verification link has expired. Please request a new one.")
    except BadSignature:
        raise ValueError("Invalid email verification token.")


def make_password_reset_token(email: str) -> str:
    """Generate a signed, time-limited password reset token."""
    return _signer().dumps(email, salt="password-reset")


def verify_password_reset_token(token: str, max_age_seconds: int = 3600) -> str:
    """
    Validate a password reset token.
    Returns the email address or raises ValueError.
    Default expiry: 1 hour.
    """
    try:
        return _signer().loads(token, salt="password-reset", max_age=max_age_seconds)
    except SignatureExpired:
        raise ValueError("Password reset link has expired. Please request a new one.")
    except BadSignature:
        raise ValueError("Invalid password reset token.")
