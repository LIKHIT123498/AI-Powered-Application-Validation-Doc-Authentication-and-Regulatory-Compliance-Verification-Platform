from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.database import get_session
from app.models.enums import UserRole
from app.models.models import Application, ChecklistRule, Document, Institution, User
from app.schemas.schemas import (
    ApplicationCreate,
    ApplicationDetailResponse,
    ApplicationValidationReportResponse,
    AuthorityVerificationResponse,
    ChecklistItemStatus,
    InstitutionCreate,
    InstitutionRead,
    ValidationFlagRead,
)
from app.services.audit_service import log_audit_event
from app.services.rules_engine import run_application_validation_engine
from app.services.security import get_current_user, require_roles
from app.services.verification_service import verify_document_with_issuing_authority

router = APIRouter(
    prefix="/api",
    tags=["Institutions & Applications (PRD §4.1)"],
)


@router.get("/institutions", response_model=List[InstitutionRead])
def list_institutions(session: Session = Depends(get_session)):
    """List registered technical institutions along with historical AICTE records."""
    return session.exec(select(Institution)).all()


@router.post(
    "/institutions",
    response_model=InstitutionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_institution(
    payload: InstitutionCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.APPLICANT])),
):
    existing = session.exec(
        select(Institution).where(
            Institution.aicte_permanent_id == payload.aicte_permanent_id
        )
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Institution with AICTE ID '{payload.aicte_permanent_id}' already exists.",
        )

    inst = Institution(**payload.model_dump())
    session.add(inst)
    session.commit()
    session.refresh(inst)

    log_audit_event(
        session,
        action_type="INSTITUTION_CREATED",
        entity_type="Institution",
        entity_id=str(inst.id),
        actor=current_user,
        summary=f"Registered institution '{inst.name}' ({inst.aicte_permanent_id}).",
    )
    return inst


@router.post(
    "/applications",
    response_model=ApplicationDetailResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_application(
    payload: ApplicationCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Create a new institutional application (e.g., Extension of Approval).
    Automatically identifies the application category, attaches the relevant
    Approval Process Handbook checklist, and retrieves historical AICTE records (PRD §4.1).
    """
    institution = session.get(Institution, payload.institution_id)
    if not institution:
        raise HTTPException(status_code=404, detail="Institution not found")

    existing_count = len(session.exec(select(Application)).all())
    app_number = f"AICTE-{payload.academic_year[:4]}-{payload.category.name}-{existing_count + 1:04d}"

    application = Application(
        application_number=app_number,
        institution_id=payload.institution_id,
        submitted_by_user_id=current_user.id,
        academic_year=payload.academic_year,
        category=payload.category,
        declared_data=payload.declared_data,
    )
    session.add(application)
    session.commit()
    session.refresh(application)

    # Fetch applicable checklist rules for this category
    rules = session.exec(
        select(ChecklistRule)
        .where(ChecklistRule.category == application.category)
        .where(ChecklistRule.is_active == True)  # noqa: E712
    ).all()

    log_audit_event(
        session,
        application_id=application.id,
        action_type="APPLICATION_INITIATED_AND_CHECKLIST_ASSIGNED",
        entity_type="Application",
        entity_id=application.application_number,
        actor=current_user,
        summary=(
            f"Application {application.application_number} created for '{institution.name}'. "
            f"Automatically matched {len(rules)} checklist rules for category '{application.category.value}' "
            f"and linked historical AICTE records."
        ),
        details={
            "category": application.category.value,
            "matched_rule_ids": [r.id for r in rules],
            "historical_eoa_ref": institution.historical_records.get("previous_eoa_reference"),
        },
    )

    return _build_application_detail(session, application, institution)


@router.get("/applications", response_model=List[Application])
def list_applications(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """List applications (Applicants see their institution's applications; Officials/Admins see all)."""
    statement = select(Application)
    if current_user.role == UserRole.APPLICANT and current_user.institution_id:
        statement = statement.where(
            Application.institution_id == current_user.institution_id
        )
    return session.exec(statement).all()


@router.get("/applications/{application_id}", response_model=ApplicationDetailResponse)
def get_application_detail(
    application_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve full application status, dynamically computed category checklist completeness,
    and historical AICTE baseline records.
    """
    application = session.get(Application, application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    institution = session.get(Institution, application.institution_id)
    return _build_application_detail(session, application, institution)


def _build_application_detail(
    session: Session,
    application: Application,
    institution: Institution,
) -> ApplicationDetailResponse:
    rules = session.exec(
        select(ChecklistRule)
        .where(ChecklistRule.category == application.category)
        .where(ChecklistRule.is_active == True)  # noqa: E712
    ).all()

    uploaded_docs = session.exec(
        select(Document).where(Document.application_id == application.id)
    ).all()
    docs_by_type = {doc.document_type: doc for doc in uploaded_docs}

    checklist_status: List[ChecklistItemStatus] = []
    for rule in rules:
        matched_doc = docs_by_type.get(rule.document_type)
        checklist_status.append(
            ChecklistItemStatus(
                rule_id=rule.id,
                document_type=rule.document_type,
                rule_name=rule.rule_name,
                is_mandatory=rule.is_mandatory,
                required_fields=rule.required_fields,
                uploaded=matched_doc is not None,
                document_id=matched_doc.id if matched_doc else None,
                verification_status=matched_doc.verification_status if matched_doc else None,
            )
        )

    return ApplicationDetailResponse(
        id=application.id,
        application_number=application.application_number,
        institution_id=application.institution_id,
        academic_year=application.academic_year,
        category=application.category,
        status=application.status,
        declared_data=application.declared_data,
        validation_summary=application.validation_summary,
        created_at=application.created_at,
        updated_at=application.updated_at,
        applicable_checklist=checklist_status,
        historical_aicte_records=institution.historical_records if institution else {},
    )


@router.post(
    "/applications/{application_id}/verify-all-documents",
    response_model=List[AuthorityVerificationResponse],
)
def verify_all_application_documents(
    application_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Triggers automated issuing-authority verification for all supporting documents
    uploaded for this application (PRD §4.3).
    """
    app_obj = session.get(Application, application_id)
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    docs = session.exec(
        select(Document).where(Document.application_id == application_id)
    ).all()

    results: List[AuthorityVerificationResponse] = []
    for doc in docs:
        status_result, details, flags = verify_document_with_issuing_authority(
            session=session,
            document=doc,
            actor_user_id=current_user.id,
        )
        results.append(
            AuthorityVerificationResponse(
                document_id=doc.id,
                document_type=doc.document_type,
                verification_status=status_result,
                issuing_authority=doc.issuing_authority,
                details=details,
                flags_created=[
                    ValidationFlagRead.model_validate(f, from_attributes=True)
                    for f in flags
                ],
                message=f"Issuing authority verification result: {status_result.value}",
            )
        )
    return results


@router.post(
    "/applications/{application_id}/validate",
    response_model=ApplicationValidationReportResponse,
)
def run_application_validation(
    application_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Executes the comprehensive regulatory rules engine and cross-document consistency checker
    (PRD §4.1, §4.2, §4.4 & Deliverables 2 & 4).
    Evaluates:
      1. Mandatory category checklist completeness & document expiries
      2. Multi-document cross-verification & AICTE baseline record consistency
      3. Infrastructure & laboratory norms
      4. Quantitative compliance scoring & actionable rectification steps
    """
    app_obj = session.get(Application, application_id)
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    report = run_application_validation_engine(
        session=session,
        application_id=application_id,
        actor_user_id=current_user.id,
    )

    return ApplicationValidationReportResponse(
        application_id=report["application_id"],
        application_number=report["application_number"],
        academic_year=report["academic_year"],
        category=report["category"],
        status=report["status"],
        overall_compliance_score=report["overall_compliance_score"],
        score_breakdown=report["score_breakdown"],
        checklist_status=report["checklist_status"],
        flag_summary=report["flag_summary"],
        open_flags=[
            ValidationFlagRead.model_validate(f, from_attributes=True)
            for f in report["open_flags"]
        ],
        rectification_steps=report["rectification_steps"],
        advisory_notes=report["advisory_notes"],
        validated_at=report["validated_at"],
    )


@router.get(
    "/applications/{application_id}/validation-report",
    response_model=ApplicationValidationReportResponse,
)
def get_application_validation_report(
    application_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the structured regulatory compliance report and open deficiency flags
    for an application (PRD §4.1).
    """
    app_obj = session.get(Application, application_id)
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    report = run_application_validation_engine(
        session=session,
        application_id=application_id,
        actor_user_id=current_user.id,
    )

    return ApplicationValidationReportResponse(
        application_id=report["application_id"],
        application_number=report["application_number"],
        academic_year=report["academic_year"],
        category=report["category"],
        status=report["status"],
        overall_compliance_score=report["overall_compliance_score"],
        score_breakdown=report["score_breakdown"],
        checklist_status=report["checklist_status"],
        flag_summary=report["flag_summary"],
        open_flags=[
            ValidationFlagRead.model_validate(f, from_attributes=True)
            for f in report["open_flags"]
        ],
        rectification_steps=report["rectification_steps"],
        advisory_notes=report["advisory_notes"],
        validated_at=report["validated_at"],
    )
