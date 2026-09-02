"""
services/audit.py — Immutable audit log writer.

Call log_event() to record any security event. Rows are never modified after
creation — this function only ever does INSERT.

Standard action codes (use these constants — never raw strings):
"""

from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from app.models.audit import AuditLog

# ------------------------------------------------------------------
# Action code constants — use these everywhere, never raw strings
# ------------------------------------------------------------------
LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILURE = "LOGIN_FAILURE"
ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
LOGOUT = "LOGOUT"
TOKEN_REFRESH = "TOKEN_REFRESH"
TOKEN_REVOKED = "TOKEN_REVOKED"
TOKEN_FAMILY_REVOKED = "TOKEN_FAMILY_REVOKED"
PASSWORD_RESET_REQ = "PASSWORD_RESET_REQ"
PASSWORD_RESET_DONE = "PASSWORD_RESET_DONE"
PASSWORD_CHANGED = "PASSWORD_CHANGED"
EMAIL_VERIFY_SENT = "EMAIL_VERIFY_SENT"
EMAIL_VERIFIED = "EMAIL_VERIFIED"
ROLE_ASSIGNED = "ROLE_ASSIGNED"
ROLE_REMOVED = "ROLE_REMOVED"
PERMISSION_ASSIGNED = "PERMISSION_ASSIGNED"
PERMISSION_REMOVED = "PERMISSION_REMOVED"
GOOGLE_LOGIN = "GOOGLE_LOGIN"
USER_REGISTERED = "USER_REGISTERED"


def log_event(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None,
) -> AuditLog:
    """
    Write a single immutable audit log entry.

    This function only ever does INSERT — never UPDATE or DELETE.
    The created_at timestamp is set server-side.
    """
    entry = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        details=json.dumps(details) if details else None,
    )
    db.add(entry)
    db.flush()  # Write immediately within the caller's transaction
    return entry
