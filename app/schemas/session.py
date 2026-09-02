"""
schemas/session.py — Session list response shape.

A "session" is a non-revoked RefreshToken row with display metadata.
last_used_at reflects the last login or token refresh — not every API call.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class SessionRead(BaseModel):
    id: int
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: datetime

    model_config = {"from_attributes": True}
