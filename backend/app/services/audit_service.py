from typing import Any, Dict, Optional
from sqlmodel import Session

from app.models.models import AuditLog, User


def log_audit_event(
    session: Session,
    *,
    action_type: str,
    entity_type: str,
    summary: str,
    application_id: Optional[int] = None,
    entity_id: Optional[str] = None,
    actor: Optional[User] = None,
    actor_role_override: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Append an immutable entry to the AuditLog table (PRD §4.5 Audit Trail).
    """
    entry = AuditLog(
        application_id=application_id,
        actor_user_id=actor.id if actor else None,
        actor_role=actor_role_override or (actor.role.value.upper() if actor else "SYSTEM"),
        action_type=action_type,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        summary=summary,
        details=details or {},
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry
