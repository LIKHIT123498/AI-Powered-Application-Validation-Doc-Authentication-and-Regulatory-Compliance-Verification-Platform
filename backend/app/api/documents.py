from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlmodel import Session, select

from app.config import settings
from app.database import get_session
from app.models.enums import (
    ApplicationStatus,
    DocumentType,
    FlagCategory,
    FlagSeverity,
    VerificationStatus,
)
from app.models.models import (
    Application,
    ChecklistRule,
    Document,
    Institution,
    User,
    ValidationFlag,
)
from app.schemas.schemas import (
    DocumentRead,
    DocumentUploadResponse,
    GeminiAIAnalysisResponse,
    ValidationFlagRead,
)
from app.services.audit_service import log_audit_event
from app.services.gemini_service import analyze_document_with_gemini
from app.services.ocr_service import compute_sha256, extract_pdf_intelligence
from app.services.sample_pdf_generator import generate_demo_pdfs
from app.services.security import get_current_user

router = APIRouter(
    prefix="/api",
    tags=["Document Upload, OCR, Forgery Forensics & Gemini AI (PRD §4.1, §4.2, §4.4)"],
)


def _parse_iso_or_common_date(date_str: Optional[str]) -> Optional[date]:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except ValueError:
            continue
    return None


@router.post("/documents/generate-sample-pdfs")
def create_sample_pdfs_for_testing():
    """
    Helper endpoint that generates 3 realistic AICTE sample PDFs in `backend/sample_docs/`:
    1. `valid_fire_safety_certificate.pdf` (clean metadata, consistent font, valid dates)
    2. `tampered_affidavit_certificate.pdf` (edited in Photoshop/iLovePDF, 5 spliced fonts, intake mismatch 600 vs 420)
    3. `deficient_infrastructure_floorplan.pdf` (classroom 48 sqm < 66 sqm, built-up area 9200 vs 14800 sqm, no ramp/lift)
    """
    paths = generate_demo_pdfs(Path("sample_docs"))
    return {
        "message": "Generated 3 sample PDFs for testing Phase 2 & Phase 3 pipelines.",
        "files": paths,
    }


@router.post(
    "/applications/{application_id}/documents",
    response_model=DocumentUploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_and_analyze_document(
    application_id: int,
    document_type: DocumentType = Form(..., description="AICTE Checklist Document Category"),
    run_ai_analysis: bool = Form(
        True,
        description="Run Google Gemini 2.5 Flash structured extraction, cross-record & infrastructure compliance analysis",
    ),
    file: UploadFile = File(..., description="PDF or image document to upload and analyze"),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Uploads a supporting document for an application and runs Phase 2 & Phase 3 pipelines:
    1. SHA-256 duplicate submission detection across the platform.
    2. PyMuPDF (`fitz`) OCR text extraction, PDF metadata inspection & font splicing forensics.
    3. Google Gemini 2.5 Flash structured JSON extraction, historical AICTE cross-verification,
       and infrastructure compliance assistance (PRD §4.1, §4.2, §4.4).
    4. Rule-based field completeness & expiry check against the matched `ChecklistRule`.
    5. Immutable `AuditLog` recording of all extracted facts and explainable AI flags.
    """
    application = session.get(Application, application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    institution = session.get(Institution, application.institution_id)

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    sha256_digest = compute_sha256(file_bytes)

    # Check if an identical file (by SHA-256 hash) already exists in the system
    existing_duplicates = session.exec(
        select(Document).where(Document.sha256_hash == sha256_digest)
    ).all()
    duplicate_detected = len(existing_duplicates) > 0

    # Save physical file in `uploads/app_<id>/`
    app_upload_dir = settings.UPLOAD_DIR / f"app_{application_id}"
    app_upload_dir.mkdir(parents=True, exist_ok=True)
    safe_filename = Path(file.filename or "document.pdf").name
    saved_path = app_upload_dir / f"{document_type.value}_{safe_filename}"
    saved_path.write_bytes(file_bytes)

    # Phase 2: Run PyMuPDF OCR, Metadata & Font Forensics
    raw_text, pdf_metadata, extracted_fields, forensic_flags = extract_pdf_intelligence(
        file_bytes=file_bytes,
        filename=safe_filename,
    )

    # Lookup matching ChecklistRule for this application's category & document_type
    matched_rule = session.exec(
        select(ChecklistRule)
        .where(ChecklistRule.category == application.category)
        .where(ChecklistRule.document_type == document_type)
        .where(ChecklistRule.is_active == True)  # noqa: E712
    ).first()

    # Phase 3: Run Google Gemini 2.5 Flash Multimodal Structured Extraction & Anomaly Analysis
    ai_analysis_output: Optional[Dict[str, Any]] = None
    if run_ai_analysis:
        inst_profile = (
            {
                "name": institution.name,
                "aicte_permanent_id": institution.aicte_permanent_id,
                "state": institution.state,
                "district": institution.district,
            }
            if institution
            else {}
        )
        hist_records = institution.historical_records if institution else {}
        rule_cfg = matched_rule.model_dump() if matched_rule else {}

        ai_analysis_output = analyze_document_with_gemini(
            file_bytes=file_bytes,
            mime_type=file.content_type or "application/pdf",
            document_type=document_type,
            raw_ocr_text=raw_text,
            pdf_metadata=pdf_metadata,
            baseline_extracted_fields=extracted_fields,
            institution_profile=inst_profile,
            historical_records=hist_records,
            rule_config=rule_cfg,
        )
        # Merge Gemini structured fields into extracted_fields
        for k, v in (ai_analysis_output.get("extracted_fields") or {}).items():
            if v is not None and (k not in extracted_fields or extracted_fields.get(k) in (None, "")):
                extracted_fields[k] = v

    doc_urn = (
        extracted_fields.get("certificate_number")
        or extracted_fields.get("eoa_reference_number")
        or extracted_fields.get("stamp_paper_number")
    )

    verification_details: Dict[str, Any] = {}
    if ai_analysis_output:
        verification_details["ai_analysis"] = {
            "ai_provider": ai_analysis_output["ai_provider"],
            "document_summary": ai_analysis_output["document_summary"],
            "authenticity_confidence_score": ai_analysis_output["authenticity_confidence_score"],
            "infrastructure_observations": ai_analysis_output["infrastructure_observations"],
            "advisory_recommendation": ai_analysis_output["advisory_recommendation"],
        }

    document = Document(
        application_id=application.id,
        document_type=document_type,
        filename=safe_filename,
        file_path=str(saved_path),
        mime_type=file.content_type or "application/pdf",
        file_size_bytes=len(file_bytes),
        sha256_hash=sha256_digest,
        raw_ocr_text=raw_text,
        pdf_metadata=pdf_metadata,
        extracted_fields=extracted_fields,
        issuing_authority=extracted_fields.get("issuing_authority"),
        document_urn_or_id=doc_urn,
        issue_date=extracted_fields.get("issue_date"),
        expiry_date=extracted_fields.get("expiry_date"),
        verification_status=VerificationStatus.PENDING,
        verification_details=verification_details,
    )
    session.add(document)
    session.commit()
    session.refresh(document)

    created_flags: List[ValidationFlag] = []

    # 1. Flag Duplicate Submission if SHA-256 matches an existing document
    if duplicate_detected:
        first_dup = existing_duplicates[0]
        dup_flag = ValidationFlag(
            application_id=application.id,
            document_id=document.id,
            rule_id=matched_rule.id if matched_rule else None,
            flag_category=FlagCategory.DUPLICATE_SUBMISSION,
            severity=FlagSeverity.HIGH,
            field_name="sha256_hash",
            reason=(
                f"Exact duplicate file detected (SHA-256 collision with Document #{first_dup.id} "
                f"in Application #{first_dup.application_id} as '{first_dup.document_type.value}')."
            ),
            evidence_snippet=f"SHA-256: {sha256_digest}",
            page_number=1,
        )
        session.add(dup_flag)
        created_flags.append(dup_flag)

    # 2. Persist PyMuPDF Forensic & Metadata Tampering Flags
    for f_data in forensic_flags:
        flag_obj = ValidationFlag(
            application_id=application.id,
            document_id=document.id,
            rule_id=matched_rule.id if matched_rule else None,
            flag_category=f_data["flag_category"],
            severity=f_data["severity"],
            field_name=f_data.get("field_name"),
            reason=f_data["reason"],
            evidence_snippet=f_data.get("evidence_snippet"),
            page_number=f_data.get("page_number"),
        )
        session.add(flag_obj)
        created_flags.append(flag_obj)

    # 3. Persist Gemini AI Semantic, Consistency & Infrastructure Flags (avoiding duplicate field+category)
    if ai_analysis_output:
        existing_keys = {(f.flag_category, f.field_name) for f in created_flags}
        for ai_flag in ai_analysis_output.get("explainable_flags", []):
            key = (ai_flag["flag_category"], ai_flag.get("field_name"))
            if key not in existing_keys:
                flag_obj = ValidationFlag(
                    application_id=application.id,
                    document_id=document.id,
                    rule_id=matched_rule.id if matched_rule else None,
                    flag_category=ai_flag["flag_category"],
                    severity=ai_flag["severity"],
                    field_name=ai_flag.get("field_name"),
                    reason=ai_flag["reason"],
                    evidence_snippet=ai_flag.get("evidence_snippet"),
                    page_number=ai_flag.get("page_number", 1),
                )
                session.add(flag_obj)
                created_flags.append(flag_obj)
                existing_keys.add(key)

    # 4. Check Required Fields & Expiry Date from Configurable ChecklistRule
    missing_fields: List[str] = []
    if matched_rule:
        for req_field in matched_rule.required_fields:
            if req_field not in extracted_fields or extracted_fields.get(req_field) in (None, ""):
                missing_fields.append(req_field)

        if missing_fields:
            inc_flag = ValidationFlag(
                application_id=application.id,
                document_id=document.id,
                rule_id=matched_rule.id,
                flag_category=FlagCategory.INCOMPLETE_FIELD,
                severity=FlagSeverity.MEDIUM,
                field_name=", ".join(missing_fields),
                reason=(
                    f"Required fields specified by rule '{matched_rule.rule_name}' were not found "
                    f"in the uploaded {document_type.value} document: {', '.join(missing_fields)}."
                ),
                evidence_snippet=f"Extracted fields present: {list(extracted_fields.keys())}",
                page_number=1,
            )
            session.add(inc_flag)
            created_flags.append(inc_flag)

        # Check Document Expiry if rule requires it
        if matched_rule.check_expiry and document.expiry_date:
            parsed_exp = _parse_iso_or_common_date(document.expiry_date)
            today = datetime.now(timezone.utc).date()
            if parsed_exp and parsed_exp < today:
                document.verification_status = VerificationStatus.EXPIRED
                session.add(document)
                exp_flag = ValidationFlag(
                    application_id=application.id,
                    document_id=document.id,
                    rule_id=matched_rule.id,
                    flag_category=FlagCategory.EXPIRED_DOCUMENT,
                    severity=FlagSeverity.CRITICAL,
                    field_name="expiry_date",
                    reason=(
                        f"{document_type.value} expired on {parsed_exp.isoformat()} "
                        f"(prior to current check date {today.isoformat()})."
                    ),
                    evidence_snippet=f"Extracted Expiry Date: {document.expiry_date}",
                    page_number=1,
                )
                session.add(exp_flag)
                created_flags.append(exp_flag)

    session.commit()
    for flg in created_flags:
        session.refresh(flg)

    # Update Application status and validation summary
    all_app_flags = session.exec(
        select(ValidationFlag)
        .where(ValidationFlag.application_id == application.id)
        .where(ValidationFlag.is_resolved == False)  # noqa: E712
    ).all()
    all_app_docs = session.exec(
        select(Document).where(Document.application_id == application.id)
    ).all()

    application.status = (
        ApplicationStatus.DEFICIENCY_FLAGGED
        if len(all_app_flags) > 0
        else ApplicationStatus.VALIDATING
    )
    application.validation_summary = {
        "documents_uploaded": len(all_app_docs),
        "open_flags_count": len(all_app_flags),
        "last_uploaded_document": document_type.value,
        "last_ai_confidence_score": (
            ai_analysis_output["authenticity_confidence_score"]
            if ai_analysis_output
            else None
        ),
        "last_updated_at": datetime.now(timezone.utc).isoformat(),
    }
    application.updated_at = datetime.now(timezone.utc)
    session.add(application)
    session.commit()

    # Log immutable Audit Trail entry
    log_audit_event(
        session,
        application_id=application.id,
        action_type="DOCUMENT_UPLOADED_AND_AI_ANALYZED",
        entity_type="Document",
        entity_id=str(document.id),
        actor=current_user,
        summary=(
            f"Uploaded '{safe_filename}' ({document_type.value}) for Application "
            f"{application.application_number}. Extracted {len(extracted_fields)} fields and "
            f"generated {len(created_flags)} validation/AI flag(s)."
        ),
        details={
            "document_id": document.id,
            "document_type": document_type.value,
            "sha256_hash": sha256_digest,
            "duplicate_detected": duplicate_detected,
            "ai_provider": ai_analysis_output["ai_provider"] if ai_analysis_output else "disabled",
            "authenticity_confidence_score": (
                ai_analysis_output["authenticity_confidence_score"]
                if ai_analysis_output
                else None
            ),
            "extracted_fields": extracted_fields,
            "missing_required_fields": missing_fields,
            "flags_generated_count": len(created_flags),
            "flag_categories": [f.flag_category.value for f in created_flags],
        },
    )

    return DocumentUploadResponse(
        document=DocumentRead.model_validate(document, from_attributes=True),
        flags_generated=[
            ValidationFlagRead.model_validate(f, from_attributes=True)
            for f in created_flags
        ],
        duplicate_detected=duplicate_detected,
        completeness_missing_fields=missing_fields,
        ai_analysis=verification_details.get("ai_analysis"),
        message=(
            f"Document processed via PyMuPDF OCR & Gemini AI: {len(extracted_fields)} fields extracted, "
            f"{len(created_flags)} advisory flag(s) generated."
        ),
    )


@router.post(
    "/documents/{document_id}/analyze-ai",
    response_model=GeminiAIAnalysisResponse,
)
def run_gemini_analysis_on_existing_document(
    document_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    On-demand endpoint to run (or re-run) Google Gemini 2.5 Flash Structured Extraction,
    Cross-Record Consistency & Infrastructure Vision Compliance on an already uploaded document.
    """
    document = session.get(Document, document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    application = session.get(Application, document.application_id)
    institution = (
        session.get(Institution, application.institution_id) if application else None
    )
    matched_rule = (
        session.exec(
            select(ChecklistRule)
            .where(ChecklistRule.category == application.category)
            .where(ChecklistRule.document_type == document.document_type)
            .where(ChecklistRule.is_active == True)  # noqa: E712
        ).first()
        if application
        else None
    )

    file_path = Path(document.file_path)
    file_bytes = file_path.read_bytes() if file_path.exists() else b""

    inst_profile = (
        {
            "name": institution.name,
            "aicte_permanent_id": institution.aicte_permanent_id,
            "state": institution.state,
            "district": institution.district,
        }
        if institution
        else {}
    )
    hist_records = institution.historical_records if institution else {}
    rule_cfg = matched_rule.model_dump() if matched_rule else {}

    ai_output = analyze_document_with_gemini(
        file_bytes=file_bytes,
        mime_type=document.mime_type,
        document_type=document.document_type,
        raw_ocr_text=document.raw_ocr_text or "",
        pdf_metadata=document.pdf_metadata or {},
        baseline_extracted_fields=document.extracted_fields or {},
        institution_profile=inst_profile,
        historical_records=hist_records,
        rule_config=rule_cfg,
    )

    # Update extracted fields & verification_details on document
    merged_fields = dict(document.extracted_fields or {})
    merged_fields.update(ai_output.get("extracted_fields") or {})
    document.extracted_fields = merged_fields

    ver_details = dict(document.verification_details or {})
    ver_details["ai_analysis"] = {
        "ai_provider": ai_output["ai_provider"],
        "document_summary": ai_output["document_summary"],
        "authenticity_confidence_score": ai_output["authenticity_confidence_score"],
        "infrastructure_observations": ai_output["infrastructure_observations"],
        "advisory_recommendation": ai_output["advisory_recommendation"],
    }
    document.verification_details = ver_details
    session.add(document)

    # Persist any new AI flags not already recorded for this document
    existing_doc_flags = session.exec(
        select(ValidationFlag).where(ValidationFlag.document_id == document.id)
    ).all()
    existing_keys = {(f.flag_category, f.field_name) for f in existing_doc_flags}

    new_flags: List[ValidationFlag] = []
    for ai_flag in ai_output.get("explainable_flags", []):
        key = (ai_flag["flag_category"], ai_flag.get("field_name"))
        if key not in existing_keys:
            flag_obj = ValidationFlag(
                application_id=document.application_id,
                document_id=document.id,
                rule_id=matched_rule.id if matched_rule else None,
                flag_category=ai_flag["flag_category"],
                severity=ai_flag["severity"],
                field_name=ai_flag.get("field_name"),
                reason=ai_flag["reason"],
                evidence_snippet=ai_flag.get("evidence_snippet"),
                page_number=ai_flag.get("page_number", 1),
            )
            session.add(flag_obj)
            new_flags.append(flag_obj)
            existing_keys.add(key)

    session.commit()
    for nf in new_flags:
        session.refresh(nf)

    log_audit_event(
        session,
        application_id=document.application_id,
        action_type="GEMINI_AI_ANALYSIS_EXECUTED",
        entity_type="Document",
        entity_id=str(document.id),
        actor=current_user,
        actor_role_override="AI_ENGINE",
        summary=(
            f"Executed AI structured analysis ({ai_output['ai_provider']}) on Document #{document.id} "
            f"({document.document_type.value}). Confidence: {ai_output['authenticity_confidence_score']}. "
            f"New flags added: {len(new_flags)}."
        ),
        details={
            "ai_provider": ai_output["ai_provider"],
            "authenticity_confidence_score": ai_output["authenticity_confidence_score"],
            "new_flags_count": len(new_flags),
            "infrastructure_observations": ai_output["infrastructure_observations"],
        },
    )

    return GeminiAIAnalysisResponse(
        document_id=document.id,
        ai_provider=ai_output["ai_provider"],
        document_summary=ai_output["document_summary"],
        authenticity_confidence_score=ai_output["authenticity_confidence_score"],
        extracted_fields=merged_fields,
        infrastructure_observations=ai_output["infrastructure_observations"],
        advisory_recommendation=ai_output["advisory_recommendation"],
        new_flags_created=[
            ValidationFlagRead.model_validate(f, from_attributes=True)
            for f in new_flags
        ],
    )


@router.get(
    "/applications/{application_id}/documents",
    response_model=List[DocumentRead],
)
def list_application_documents(
    application_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """List all uploaded documents and their extracted OCR/metadata for an application."""
    application = session.get(Application, application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    docs = session.exec(
        select(Document).where(Document.application_id == application_id)
    ).all()
    return docs


@router.get("/documents/{document_id}", response_model=DocumentRead)
def get_document_detail(
    document_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Inspect a single document's raw OCR text, PDF metadata diagnostics, and extracted fields."""
    doc = session.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


@router.get(
    "/applications/{application_id}/flags",
    response_model=List[ValidationFlagRead],
)
def list_application_flags(
    application_id: int,
    unresolved_only: bool = False,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    List all Explainable AI & Forensic ValidationFlags for an application (PRD §4.2 & §4.5).
    """
    statement = select(ValidationFlag).where(
        ValidationFlag.application_id == application_id
    )
    if unresolved_only:
        statement = statement.where(ValidationFlag.is_resolved == False)  # noqa: E712
    return session.exec(statement).all()
