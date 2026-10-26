from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.database import get_session
from app.models.enums import ApplicationCategory, UserRole
from app.models.models import ChecklistRule, User
from app.schemas.schemas import ChecklistRuleCreate, ChecklistRuleUpdate
from app.services.audit_service import log_audit_event
from app.services.security import require_roles

router = APIRouter(
    prefix="/api/rules",
    tags=["Configurable Regulatory Rules Engine (PRD §4.1, §4.4, §5)"],
)


@router.get("", response_model=List[ChecklistRule])
def list_checklist_rules(
    category: Optional[ApplicationCategory] = None,
    handbook_year: Optional[str] = None,
    active_only: bool = True,
    session: Session = Depends(get_session),
):
    """
    Retrieve configurable checklist rules derived from the AICTE Approval Process Handbook.
    Filterable by application category (e.g., EXTENSION_OF_APPROVAL).
    """
    statement = select(ChecklistRule)
    if category:
        statement = statement.where(ChecklistRule.category == category)
    if handbook_year:
        statement = statement.where(ChecklistRule.handbook_year == handbook_year)
    if active_only:
        statement = statement.where(ChecklistRule.is_active == True)  # noqa: E712
    return session.exec(statement).all()


@router.post("", response_model=ChecklistRule, status_code=status.HTTP_201_CREATED)
def create_checklist_rule(
    payload: ChecklistRuleCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
):
    """
    (Admin Only) Add a new configurable regulatory rule based on the AICTE Approval Process Handbook.
    """
    rule = ChecklistRule(**payload.model_dump())
    session.add(rule)
    session.commit()
    session.refresh(rule)

    log_audit_event(
        session,
        action_type="CHECKLIST_RULE_CREATED",
        entity_type="ChecklistRule",
        entity_id=str(rule.id),
        actor=current_user,
        summary=f"Created rule '{rule.rule_name}' for {rule.category.value} ({rule.document_type.value}).",
        details=payload.model_dump(),
    )
    return rule


@router.patch("/{rule_id}", response_model=ChecklistRule)
def update_checklist_rule(
    rule_id: int,
    payload: ChecklistRuleUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
):
    """
    (Admin Only) Modify an existing regulatory checklist rule (PRD §5 Configurability).
    """
    rule = session.get(ChecklistRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="ChecklistRule not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(rule, key, value)
    rule.updated_at = datetime.now(timezone.utc)

    session.add(rule)
    session.commit()
    session.refresh(rule)

    log_audit_event(
        session,
        action_type="CHECKLIST_RULE_UPDATED",
        entity_type="ChecklistRule",
        entity_id=str(rule.id),
        actor=current_user,
        summary=f"Updated rule #{rule.id} ('{rule.rule_name}').",
        details=update_data,
    )
    return rule
