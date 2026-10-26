from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlmodel import Session, col, select

from app.database import get_session
from app.models.models import AuditLog, User
from app.services.security import get_current_user

router = APIRouter(
    prefix="/api/audit",
    tags=["Immutable Audit Trail (PRD §4.5)"],
)


@router.get("", response_model=List[AuditLog])
def list_audit_logs(
    application_id: Optional[int] = None,
    limit: int = 100,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Fetch immutable audit trail entries ordered newest first.
    Logs every rule applied, record checked, alert generated, and user action.
    """
    statement = select(AuditLog).order_by(col(AuditLog.timestamp).desc()).limit(limit)
    if application_id is not None:
        statement = statement.where(AuditLog.application_id == application_id)
    return session.exec(statement).all()
