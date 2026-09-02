"""
services/oauth.py — Google OAuth token verification.

The Google Sign-In endpoint is disabled automatically when GOOGLE_CLIENT_ID
is not set in .env. The service raises ServiceUnavailableError in that case
so routes can return 503 cleanly.

No Apple Sign-In in V1 (requires paid Apple Developer account — Phase 2).
"""

from __future__ import annotations

from fastapi import HTTPException, status
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from app.config import settings


class GoogleTokenInfo:
    """Parsed information extracted from a verified Google id_token."""

    def __init__(self, google_id: str, email: str, email_verified: bool) -> None:
        self.google_id = google_id
        self.email = email
        self.email_verified = email_verified


def verify_google_token(token: str) -> GoogleTokenInfo:
    """
    Verify a Google id_token and return parsed user info.

    Raises:
        HTTPException(503) if GOOGLE_CLIENT_ID is not configured.
        HTTPException(401) if the token is invalid or expired.
    """
    if not settings.google_oauth_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Google Sign-In is not configured. "
                "Set GOOGLE_CLIENT_ID in your .env file to enable it."
            ),
        )

    try:
        info = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            settings.GOOGLE_CLIENT_ID,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google token: {exc}",
        ) from exc

    google_sub = info.get("sub")
    email = info.get("email")
    email_verified = info.get("email_verified", False)

    if not google_sub or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token missing required fields (sub, email).",
        )

    return GoogleTokenInfo(
        google_id=google_sub,
        email=email,
        email_verified=bool(email_verified),
    )
