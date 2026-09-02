"""
routers/audit.py — Audit log viewer. Admin only.

V1: Simple list of recent audit logs (no filters/pagination beyond limit/skip).
Phase 2: Full queryable API with date range, action filter, user filter, and export.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.core import ApiResponse

router = APIRouter()


class AuditLogRead(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/logs", response_model=ApiResponse[list[AuditLogRead]])
def list_audit_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """
    List recent audit log entries. Admin only.

    Phase 2 TODO: Add filters (action, user_id, date range) and pagination headers.
    """
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return ApiResponse(status=True, statusCode=200, message="Success", data=logs)
