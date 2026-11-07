from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, col, select

from app.database import get_session
from app.models.enums import (
    ApplicationStatus,
    FlagCategory,
    FlagSeverity,
    UserRole,
    VerificationStatus,
)
from app.models.models import (
    Application,
    AuditLog,
    ChecklistRule,
    Document,
    Institution,
    User,
    ValidationFlag,
)
from app.schemas.schemas import (
    ApplicationDecisionRequest,
    ApplicationDecisionResponse,
    DashboardApplicationSummary,
    DashboardMetricsResponse,
    FlagReviewRequest,
    ValidationFlagRead,
)
from app.services.audit_service import log_audit_event
from app.services.security import get_current_user, require_roles

router = APIRouter(
    prefix="/api",
    tags=["Reviewer Dashboard, Alerts & Human-in-the-Loop Actions (PRD §4.5)"],
)


@router.get("/dashboard/metrics", response_model=DashboardMetricsResponse)
def get_dashboard_metrics(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Centralized Dashboard metrics for AICTE Reviewers & System Admins (PRD §4.5).
    Provides real-time application counts, status breakdown, AI flag distributions,
    issuing-authority verification rates, and pending scrutiny actions.
    """
    all_apps = session.exec(select(Application)).all()
    all_flags = session.exec(
        select(ValidationFlag).where(ValidationFlag.is_resolved == False)  # noqa: E712
    ).all()
    all_docs = session.exec(select(Document)).all()

    # Status distribution
    status_dist: Dict[str, int] = {s.value: 0 for s in ApplicationStatus}
    for app in all_apps:
        status_dist[app.status.value] = status_dist.get(app.status.value, 0) + 1

    # Open flag severity distribution
    flag_dist: Dict[str, int] = {sev.value: 0 for sev in FlagSeverity}
    for flg in all_flags:
        flag_dist[flg.severity.value] = flag_dist.get(flg.severity.value, 0) + 1

    # Authority verification breakdown
    ver_stats: Dict[str, int] = {v.value: 0 for v in VerificationStatus}
    for d in all_docs:
        ver_stats[d.verification_status.value] = (
            ver_stats.get(d.verification_status.value, 0) + 1
        )

    # Average compliance score
    scores = [
        app.validation_summary.get("overall_compliance_score")
        for app in all_apps
        if app.validation_summary
        and app.validation_summary.get("overall_compliance_score") is not None
    ]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    # Pending scrutiny count (applications in VALIDATING, DEFICIENCY_FLAGGED, or READY_FOR_REVIEW)
    pending_count = sum(
        1
        for a in all_apps
        if a.status
        in (
            ApplicationStatus.VALIDATING,
            ApplicationStatus.DEFICIENCY_FLAGGED,
            ApplicationStatus.READY_FOR_REVIEW,
        )
    )

    # Build summary objects for recent applications
    recent_apps_summary: List[DashboardApplicationSummary] = []
    # Sort descending by created_at
    sorted_apps = sorted(all_apps, key=lambda a: a.created_at, reverse=True)[:10]

    for app in sorted_apps:
        inst = session.get(Institution, app.institution_id)
        open_app_flags = [f for f in all_flags if f.application_id == app.id]
        crit_flags = sum(1 for f in open_app_flags if f.severity == FlagSeverity.CRITICAL)
        doc_count = sum(1 for d in all_docs if d.application_id == app.id)

        recent_apps_summary.append(
            DashboardApplicationSummary(
                id=app.id,
                application_number=app.application_number,
                institution_name=inst.name if inst else "Unknown Institution",
                aicte_permanent_id=inst.aicte_permanent_id if inst else "N/A",
                category=app.category,
                status=app.status,
                overall_compliance_score=(
                    app.validation_summary.get("overall_compliance_score")
                    if app.validation_summary
                    else None
                ),
                open_flags_count=len(open_app_flags),
                critical_flags_count=crit_flags,
                documents_uploaded=doc_count,
                created_at=app.created_at,
            )
        )

    # Top recent unresolved flags (ordered by critical/high first)
    sorted_flags = sorted(
        all_flags,
        key=lambda f: (
            0
            if f.severity == FlagSeverity.CRITICAL
            else (1 if f.severity == FlagSeverity.HIGH else 2)
        ),
    )[:10]

    return DashboardMetricsResponse(
        total_applications=len(all_apps),
        status_distribution=status_dist,
        flag_distribution=flag_dist,
        authority_verification_stats=ver_stats,
        average_compliance_score=avg_score,
        pending_scrutiny_count=pending_count,
        recent_applications=recent_apps_summary,
        recent_open_flags=[
            ValidationFlagRead.model_validate(f, from_attributes=True)
            for f in sorted_flags
        ],
    )


@router.post(
    "/flags/{flag_id}/review",
    response_model=ValidationFlagRead,
)
def review_validation_flag(
    flag_id: int,
    payload: FlagReviewRequest,
    session: Session = Depends(get_session),
    current_user: User = Depends(
        require_roles([UserRole.REVIEWER, UserRole.ADMIN])
    ),
):
    """
    PRD §4.2 & §5: Human-in-the-Loop decision action on an AI/regulatory flag.
    AICTE Officials can:
      - CONFIRMED_DEFICIENCY: Uphold deficiency as valid.
      - DISMISSED_FALSE_POSITIVE: Dismiss benign warning or false positive.
      - REQUEST_RECTIFICATION: Mark for applicant rectification.
    """
    flag = session.get(ValidationFlag, flag_id)
    if not flag:
        raise HTTPException(status_code=404, detail="Validation flag not found")

    now = datetime.now(timezone.utc)
    flag.is_resolved = True
    flag.reviewer_action = payload.action.value
    flag.reviewer_notes = payload.reviewer_notes
    flag.reviewed_by_user_id = current_user.id
    flag.reviewed_at = now
    session.add(flag)
    session.commit()
    session.refresh(flag)

    # Check if this resolves all critical/high flags for the application
    app = session.get(Application, flag.application_id)
    if app:
        remaining_unresolved = session.exec(
            select(ValidationFlag)
            .where(ValidationFlag.application_id == app.id)
            .where(ValidationFlag.is_resolved == False)  # noqa: E712
        ).all()

        crit_or_high = [
            f
            for f in remaining_unresolved
            if f.severity in (FlagSeverity.CRITICAL, FlagSeverity.HIGH)
        ]

        if not crit_or_high and app.status == ApplicationStatus.DEFICIENCY_FLAGGED:
            app.status = ApplicationStatus.READY_FOR_REVIEW
            app.updated_at = now
            session.add(app)
            session.commit()

    # Log immutable audit event
    log_audit_event(
        session,
        application_id=flag.application_id,
        action_type="FLAG_REVIEWED_BY_OFFICIAL",
        entity_type="ValidationFlag",
        entity_id=str(flag.id),
        actor=current_user,
        summary=(
            f"Official {current_user.full_name} reviewed Flag #{flag.id} ({flag.flag_category.value}) "
            f"with action '{payload.action.value}'. Notes: {payload.reviewer_notes or 'None'}."
        ),
        details={
            "flag_id": flag.id,
            "action": payload.action.value,
            "reviewer_notes": payload.reviewer_notes,
            "field_name": flag.field_name,
        },
    )

    return ValidationFlagRead.model_validate(flag, from_attributes=True)


@router.post(
    "/applications/{application_id}/decision",
    response_model=ApplicationDecisionResponse,
)
def record_application_decision(
    application_id: int,
    payload: ApplicationDecisionRequest,
    session: Session = Depends(get_session),
    current_user: User = Depends(
        require_roles([UserRole.REVIEWER, UserRole.ADMIN])
    ),
):
    """
    PRD §2.3 & §5: Final regulatory decision-making by competent AICTE authority.
    The system provides decision-support; statutory approval/rejection remains with the human official.
    Actions:
      - APPROVE: Grant Extension of Approval / institutional clearance.
      - REJECT: Refuse application based on confirmed handbook deficiencies.
      - REQUEST_RECTIFICATION: Issue an official notice to the applicant institution.
    """
    app = session.get(Application, application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    now = datetime.now(timezone.utc)

    if payload.decision.value == "APPROVE":
        app.status = ApplicationStatus.APPROVED_BY_REVIEWER
    elif payload.decision.value == "REJECT":
        app.status = ApplicationStatus.REJECTED_BY_REVIEWER
    elif payload.decision.value == "REQUEST_RECTIFICATION":
        app.status = ApplicationStatus.RECTIFICATION_REQUESTED

    summary_data = dict(app.validation_summary or {})
    summary_data["official_decision"] = {
        "decision": payload.decision.value,
        "decision_notes": payload.decision_notes,
        "rectification_notice": payload.rectification_notice,
        "reviewed_by": current_user.full_name,
        "reviewed_by_email": current_user.email,
        "decided_at": now.isoformat(),
    }
    app.validation_summary = summary_data
    app.updated_at = now
    session.add(app)
    session.commit()
    session.refresh(app)

    # Log immutable audit event
    log_audit_event(
        session,
        application_id=app.id,
        action_type="APPLICATION_DECISION_SUBMITTED",
        entity_type="Application",
        entity_id=app.application_number,
        actor=current_user,
        summary=(
            f"Official {current_user.full_name} submitted statutory decision '{payload.decision.value}' "
            f"for Application {app.application_number}. Status updated to '{app.status.value}'."
        ),
        details={
            "decision": payload.decision.value,
            "decision_notes": payload.decision_notes,
            "rectification_notice": payload.rectification_notice,
        },
    )

    return ApplicationDecisionResponse(
        application_id=app.id,
        application_number=app.application_number,
        status=app.status,
        reviewer_decision=payload.decision.value,
        decision_notes=payload.decision_notes,
        reviewed_by=current_user.full_name,
        timestamp=now,
    )
