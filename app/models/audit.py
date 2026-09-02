"""
models/audit.py — Immutable AuditLog model.

Records every significant security event. Rows are never updated or deleted
after creation — append-only for compliance and forensic integrity.

Standard action codes:
  LOGIN_SUCCESS        LOGIN_FAILURE        ACCOUNT_LOCKED
  TOKEN_REFRESH        TOKEN_REVOKED        LOGOUT
  PASSWORD_RESET_REQ   PASSWORD_RESET_DONE  PASSWORD_CHANGED
  EMAIL_VERIFY_SENT    EMAIL_VERIFIED
  ROLE_ASSIGNED        ROLE_REMOVED
  PERMISSION_ASSIGNED  PERMISSION_REMOVED
  GOOGLE_LOGIN
"""

from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    # user_id is nullable — failed logins may not have a resolved user
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Standard action code — see module docstring for full list
    action = Column(String(50), nullable=False, index=True)

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)

    # JSON string with any extra contextual data (e.g. role name, permission code)
    details = Column(Text, nullable=True)

    # Server-side timestamp — cannot be set by application code
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action!r} user_id={self.user_id}>"
