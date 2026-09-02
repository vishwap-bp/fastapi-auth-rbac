"""
models/token.py — RefreshToken ORM model.

This table serves two purposes intentionally:
  1. Security: refresh token validation (jti, family_id, is_revoked, expires_at)
  2. Session display: user-visible session list (ip_address, user_agent, last_used_at)

Single source of truth — no second session table needed.

RULE (Architecture Rule 2):
  last_used_at is updated ONLY in services/token.py at login and refresh.
  It is NEVER updated in deps.py on access-token validation.
  Column comment documents this for future developers.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)

    # UUID string — unique ID of this specific token
    jti = Column(String(36), unique=True, nullable=False, index=True)

    # UUID string — shared across all tokens in one refresh chain.
    # If a revoked token's jti is replayed, ALL tokens with this family_id
    # are revoked immediately (compromise detection).
    family_id = Column(String(36), nullable=False, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    is_revoked = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # Session display fields
    ip_address = Column(String(45), nullable=True)   # IPv4 or IPv6
    user_agent = Column(String(512), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # RULE: Updated on login and token refresh ONLY.
    # Does NOT reflect every API call — see Architecture Rule 2 in docs.
    last_used_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment=(
            "Updated on login and token refresh only. "
            "Does NOT reflect every authenticated API call. See Architecture Rule 2."
        ),
    )

    user = relationship("User", back_populates="refresh_tokens")

    def __repr__(self) -> str:
        return f"<RefreshToken jti={self.jti!r} revoked={self.is_revoked}>"
