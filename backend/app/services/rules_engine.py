from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional
from sqlmodel import Session, select

from app.models.enums import (
    ApplicationStatus,
    DocumentType,
    FlagCategory,
    FlagSeverity,
    VerificationStatus,
)
from app.models.models import (
    Application,
    AuditLog,
    ChecklistRule,
    Document,
    Institution,
    ValidationFlag,
)
from app.services.audit_service import log_audit_event


def _parse_common_date(date_str: Optional[str]) -> Optional[date]:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except ValueError:
            continue
    return None


def run_application_validation_engine(
    session: Session,
    application_id: int,
    actor_user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Configurable regulatory validation rules engine and cross-document consistency checker
    (PRD §4.1, §4.2, §4.4, §5 & Deliverables 2 & 4).

    Executes 4 comprehensive validation steps:
      1. Category Checklist Completeness & Expiry Checks
      2. Multi-Document Cross-Verification & AICTE Historical Data Consistency
      3. Infrastructure & Laboratory Norms Compliance
      4. Quantitative Compliance Scoring & Actionable Rectification Advisory Report
    """
    now = datetime.now(timezone.utc)
    today = now.date()

    application = session.get(Application, application_id)
    if not application:
        raise ValueError(f"Application #{application_id} not found")

    institution = session.get(Institution, application.institution_id)
    historical_records = institution.historical_records if institution else {}
    declared_data = application.declared_data or {}

    # Fetch applicable active checklist rules for this application category
    rules = session.exec(
        select(ChecklistRule)
        .where(ChecklistRule.category == application.category)
        .where(ChecklistRule.is_active == True)  # noqa: E712
    ).all()

    # Fetch all uploaded documents for this application
    documents = session.exec(
        select(Document).where(Document.application_id == application_id)
    ).all()
    docs_by_type: Dict[DocumentType, List[Document]] = {}
    for d in documents:
        docs_by_type.setdefault(d.document_type, []).append(d)

    # Existing flags to avoid duplicate insertion
    existing_flags = session.exec(
        select(ValidationFlag).where(ValidationFlag.application_id == application_id)
    ).all()
    existing_keys = {
        (
            f.flag_category,
            f.document_id,
            f.field_name,
            f.reason[:60] if f.reason else "",
        )
        for f in existing_flags
    }

    new_flags: List[ValidationFlag] = []

    def add_flag(
        *,
        flag_category: FlagCategory,
        severity: FlagSeverity,
        field_name: Optional[str],
        reason: str,
        evidence_snippet: Optional[str] = None,
        document_id: Optional[int] = None,
        rule_id: Optional[int] = None,
        page_number: Optional[int] = 1,
    ):
        key = (
            flag_category,
            document_id,
            field_name,
            reason[:60] if reason else "",
        )
        if key not in existing_keys:
            flag_obj = ValidationFlag(
                application_id=application.id,
                document_id=document_id,
                rule_id=rule_id,
                flag_category=flag_category,
                severity=severity,
                field_name=field_name,
                reason=reason,
                evidence_snippet=evidence_snippet,
                page_number=page_number,
            )
            session.add(flag_obj)
            new_flags.append(flag_obj)
            existing_keys.add(key)

    # -------------------------------------------------------------------------
    # STEP 1: Category Checklist Completeness & Document Expiry Checks
    # -------------------------------------------------------------------------
    mandatory_rules_count = 0
    mandatory_uploaded_count = 0

    checklist_item_details = []
    for rule in rules:
        if rule.is_mandatory:
            mandatory_rules_count += 1

        matched_docs = docs_by_type.get(rule.document_type, [])
        is_uploaded = len(matched_docs) > 0

        if is_uploaded:
            if rule.is_mandatory:
                mandatory_uploaded_count += 1
            # Check fields completeness and expiry for each uploaded document of this type
            for doc in matched_docs:
                extracted = doc.extracted_fields or {}
                missing_fields = [
                    rf
                    for rf in rule.required_fields
                    if rf not in extracted or extracted.get(rf) in (None, "")
                ]
                if missing_fields:
                    add_flag(
                        flag_category=FlagCategory.INCOMPLETE_FIELD,
                        severity=FlagSeverity.MEDIUM,
                        field_name=", ".join(missing_fields),
                        reason=(
                            f"Mandatory fields missing in uploaded {rule.document_type.value}: "
                            f"{', '.join(missing_fields)} (Required by rule '{rule.rule_name}')."
                        ),
                        evidence_snippet=f"Fields present: {list(extracted.keys())}",
                        document_id=doc.id,
                        rule_id=rule.id,
                    )

                if rule.check_expiry and doc.expiry_date:
                    exp_dt = _parse_common_date(doc.expiry_date)
                    if exp_dt and exp_dt < today:
                        add_flag(
                            flag_category=FlagCategory.EXPIRED_DOCUMENT,
                            severity=FlagSeverity.CRITICAL,
                            field_name="expiry_date",
                            reason=(
                                f"Uploaded {rule.document_type.value} has expired on {exp_dt.isoformat()} "
                                f"(prior to scrutiny date {today.isoformat()})."
                            ),
                            evidence_snippet=f"Expiry Date on Doc: {doc.expiry_date}",
                            document_id=doc.id,
                            rule_id=rule.id,
                        )
        else:
            if rule.is_mandatory:
                add_flag(
                    flag_category=FlagCategory.MISSING_DOCUMENT,
                    severity=FlagSeverity.CRITICAL,
                    field_name=rule.document_type.value,
                    reason=(
                        f"Mandatory document '{rule.document_type.value}' is missing. "
                        f"Required by AICTE Approval Process Handbook rule: '{rule.rule_name}'."
                    ),
                    evidence_snippet=f"Rule ID: {rule.id} | Handbook Year: {rule.handbook_year}",
                    rule_id=rule.id,
                )

        checklist_item_details.append(
            {
                "rule_id": rule.id,
                "document_type": rule.document_type.value,
                "rule_name": rule.rule_name,
                "is_mandatory": rule.is_mandatory,
                "uploaded": is_uploaded,
                "uploaded_docs_count": len(matched_docs),
            }
        )

    # -------------------------------------------------------------------------
    # STEP 2: Cross-Document Consistency & AICTE Historical Data Verification
    # -------------------------------------------------------------------------
    # Aggregate extracted fields across all uploaded documents
    doc_fields_map: Dict[int, Dict[str, Any]] = {
        d.id: (d.extracted_fields or {}) for d in documents
    }

    # A. Cross-verify Institution Name across documents
    expected_inst_name = institution.name if institution else None
    for doc in documents:
        extracted = doc_fields_map[doc.id]
        doc_inst_name = extracted.get("institution_name")
        if doc_inst_name and expected_inst_name:
            if doc_inst_name.strip().lower() != expected_inst_name.strip().lower():
                add_flag(
                    flag_category=FlagCategory.CROSS_DOC_INCONSISTENCY,
                    severity=FlagSeverity.HIGH,
                    field_name="institution_name",
                    reason=(
                        f"Institution name in '{doc.filename}' ({doc.document_type.value}) does not match "
                        f"registered AICTE institution profile ('{expected_inst_name}')."
                    ),
                    evidence_snippet=f"Doc Value: '{doc_inst_name}' vs Profile: '{expected_inst_name}'",
                    document_id=doc.id,
                )

    # B. Cross-verify AICTE Permanent ID across documents
    expected_aicte_id = institution.aicte_permanent_id if institution else None
    for doc in documents:
        extracted = doc_fields_map[doc.id]
        doc_aicte_id = extracted.get("aicte_permanent_id")
        if doc_aicte_id and expected_aicte_id:
            if doc_aicte_id.strip() != expected_aicte_id.strip():
                add_flag(
                    flag_category=FlagCategory.CROSS_DOC_INCONSISTENCY,
                    severity=FlagSeverity.CRITICAL,
                    field_name="aicte_permanent_id",
                    reason=(
                        f"AICTE Permanent ID in '{doc.filename}' ({doc_aicte_id}) differs from "
                        f"institution master record ({expected_aicte_id})."
                    ),
                    evidence_snippet=f"Doc AICTE ID: {doc_aicte_id} | Master AICTE ID: {expected_aicte_id}",
                    document_id=doc.id,
                )

    # C. Cross-verify Building & Built-up Area across documents & historical records
    # Compare Fire Safety Certificate vs Building Plan / Infrastructure Evidence
    fire_docs = docs_by_type.get(DocumentType.FIRE_SAFETY_CERTIFICATE, [])
    infra_docs = (
        docs_by_type.get(DocumentType.BUILDING_PLAN_CERTIFICATE, [])
        + docs_by_type.get(DocumentType.INFRASTRUCTURE_EVIDENCE, [])
    )

    for f_doc in fire_docs:
        f_area = (f_doc.extracted_fields or {}).get("building_area_sqm") or (f_doc.extracted_fields or {}).get("built_up_area_sqm")
        if f_area:
            for i_doc in infra_docs:
                i_area = (i_doc.extracted_fields or {}).get("built_up_area_sqm") or (i_doc.extracted_fields or {}).get("building_area_sqm")
                if i_area and abs(float(f_area) - float(i_area)) > 50:
                    add_flag(
                        flag_category=FlagCategory.CROSS_DOC_INCONSISTENCY,
                        severity=FlagSeverity.HIGH,
                        field_name="built_up_area_sqm",
                        reason=(
                            f"Discrepancy in certified built-up area between Fire Safety Certificate "
                            f"({f_area} sqm in '{f_doc.filename}') and Infrastructure Evidence "
                            f"({i_area} sqm in '{i_doc.filename}')."
                        ),
                        evidence_snippet=f"Fire Safety Area: {f_area} sqm != Infrastructure Area: {i_area} sqm",
                        document_id=i_doc.id,
                    )

    # D. Cross-verify Approved Intake between EoA Letter, Affidavit & Declared Form Data
    eoa_docs = docs_by_type.get(DocumentType.PREVIOUS_EOA_LETTER, [])
    affidavit_docs = docs_by_type.get(DocumentType.AFFIDAVIT, [])
    historical_intake = historical_records.get("approved_intake_total")

    for aff_doc in affidavit_docs:
        aff_intake = (aff_doc.extracted_fields or {}).get("approved_intake_total")
        if aff_intake and historical_intake:
            if int(aff_intake) != int(historical_intake):
                add_flag(
                    flag_category=FlagCategory.CROSS_DOC_INCONSISTENCY,
                    severity=FlagSeverity.HIGH,
                    field_name="approved_intake_total",
                    reason=(
                        f"Intake declared in Affidavit '{aff_doc.filename}' ({aff_intake}) does not match "
                        f"authorized baseline in AICTE Central Records ({historical_intake})."
                    ),
                    evidence_snippet=f"Affidavit: {aff_intake} vs Historical EoA Record: {historical_intake}",
                    document_id=aff_doc.id,
                )

    # -------------------------------------------------------------------------
    # STEP 3: Infrastructure Norms Verification (Approval Process Handbook)
    # -------------------------------------------------------------------------
    for i_doc in infra_docs:
        extracted = i_doc.extracted_fields or {}
        cr_area = extracted.get("min_classroom_area_sqm")
        if cr_area and float(cr_area) < 66.0:
            add_flag(
                flag_category=FlagCategory.INFRASTRUCTURE_DISCREPANCY,
                severity=FlagSeverity.HIGH,
                field_name="min_classroom_area_sqm",
                reason=(
                    f"Classroom area of {cr_area} sqm in '{i_doc.filename}' fails the mandatory "
                    "AICTE Approval Process Handbook minimum standard of 66 sqm."
                ),
                evidence_snippet=f"Reported Classroom Area: {cr_area} sqm < Required 66 sqm",
                document_id=i_doc.id,
            )

        lab_area = extracted.get("min_laboratory_area_sqm")
        if lab_area and float(lab_area) < 66.0:
            add_flag(
                flag_category=FlagCategory.INFRASTRUCTURE_DISCREPANCY,
                severity=FlagSeverity.HIGH,
                field_name="min_laboratory_area_sqm",
                reason=(
                    f"Laboratory area of {lab_area} sqm in '{i_doc.filename}' is below the mandatory "
                    "AICTE Handbook norm of 66 sqm."
                ),
                evidence_snippet=f"Reported Laboratory Area: {lab_area} sqm < Required 66 sqm",
                document_id=i_doc.id,
            )

        barrier_free = extracted.get("barrier_free_environment")
        if barrier_free is False:
            add_flag(
                flag_category=FlagCategory.INFRASTRUCTURE_DISCREPANCY,
                severity=FlagSeverity.MEDIUM,
                field_name="barrier_free_environment",
                reason=(
                    f"Infrastructure report '{i_doc.filename}' indicates non-compliance or absence of "
                    "barrier-free environment (ramps/elevators/accessible amenities for PwD)."
                ),
                evidence_snippet="Barrier-free environment: Non-Compliant / Missing",
                document_id=i_doc.id,
            )

    # Commit any newly generated flags
    session.commit()
    for nf in new_flags:
        session.refresh(nf)

    # Fetch all active open flags for the application
    all_open_flags = session.exec(
        select(ValidationFlag)
        .where(ValidationFlag.application_id == application_id)
        .where(ValidationFlag.is_resolved == False)  # noqa: E712
    ).all()

    # -------------------------------------------------------------------------
    # STEP 4: Compliance Scoring & Actionable Rectification Advisory
    # -------------------------------------------------------------------------
    crit_count = sum(1 for f in all_open_flags if f.severity == FlagSeverity.CRITICAL)
    high_count = sum(1 for f in all_open_flags if f.severity == FlagSeverity.HIGH)
    med_count = sum(1 for f in all_open_flags if f.severity == FlagSeverity.MEDIUM)
    low_count = sum(1 for f in all_open_flags if f.severity == FlagSeverity.LOW)

    completeness_score = (
        round((mandatory_uploaded_count / mandatory_rules_count) * 100, 1)
        if mandatory_rules_count > 0
        else 100.0
    )

    verified_docs_count = sum(
        1 for d in documents if d.verification_status == VerificationStatus.VERIFIED
    )
    verification_score = (
        round((verified_docs_count / len(documents)) * 100, 1)
        if documents
        else 0.0
    )

    # Overall Compliance Score out of 100
    penalty = (crit_count * 25) + (high_count * 15) + (med_count * 5) + (low_count * 2)
    overall_score = max(0.0, min(100.0, round(completeness_score * 0.4 + verification_score * 0.3 + max(0, 100 - penalty) * 0.3, 1)))

    # Determine recommended status
    if crit_count > 0:
        recommended_status = ApplicationStatus.DEFICIENCY_FLAGGED
    elif high_count > 0 or completeness_score < 100.0:
        recommended_status = ApplicationStatus.RECTIFICATION_REQUESTED
    elif med_count > 0:
        recommended_status = ApplicationStatus.DEFICIENCY_FLAGGED
    else:
        recommended_status = ApplicationStatus.READY_FOR_REVIEW

    # Actionable rectification advice for the applicant (PRD §4.1)
    rectification_steps: List[str] = []
    if completeness_score < 100.0:
        missing_names = [
            item["rule_name"]
            for item in checklist_item_details
            if item["is_mandatory"] and not item["uploaded"]
        ]
        rectification_steps.append(
            f"Upload missing mandatory document(s): {'; '.join(missing_names)}."
        )

    for flg in all_open_flags:
        if flg.flag_category == FlagCategory.EXPIRED_DOCUMENT:
            rectification_steps.append(
                f"Renew expired document ({flg.field_name}): {flg.reason}"
            )
        elif flg.flag_category == FlagCategory.POTENTIAL_FORGERY_OR_ALTERATION:
            rectification_steps.append(
                f"Replace suspect file or provide original digitally signed PDF: {flg.reason}"
            )
        elif flg.flag_category == FlagCategory.CROSS_DOC_INCONSISTENCY:
            rectification_steps.append(
                f"Reconcile data mismatch for '{flg.field_name}': {flg.reason}"
            )
        elif flg.flag_category == FlagCategory.INFRASTRUCTURE_DISCREPANCY:
            rectification_steps.append(
                f"Address infrastructure shortfall for '{flg.field_name}': {flg.reason}"
            )

    # Remove duplicates from rectification steps
    rectification_steps = list(dict.fromkeys(rectification_steps))

    # Update Application state
    application.status = recommended_status
    validation_summary = {
        "overall_compliance_score": overall_score,
        "completeness_score": completeness_score,
        "authority_verification_score": verification_score,
        "mandatory_rules_total": mandatory_rules_count,
        "mandatory_uploaded_total": mandatory_uploaded_count,
        "total_documents_uploaded": len(documents),
        "total_open_flags": len(all_open_flags),
        "flag_breakdown": {
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "last_validated_at": now.isoformat(),
        "recommended_decision": (
            "Ready for AICTE Scrutiny Committee Approval"
            if recommended_status == ApplicationStatus.READY_FOR_REVIEW
            else "Rectification Notice Required: Outstanding deficiencies must be addressed by institution."
        ),
    }
    application.validation_summary = validation_summary
    application.updated_at = now
    session.add(application)
    session.commit()

    # Log immutable audit event
    log_audit_event(
        session,
        application_id=application.id,
        action_type="APPLICATION_COMPLIANCE_VALIDATED",
        entity_type="Application",
        entity_id=application.application_number,
        actor_role_override="REGULATORY_RULES_ENGINE",
        summary=(
            f"Executed regulatory rules engine for Application {application.application_number}. "
            f"Compliance Score: {overall_score}%. Flags: {len(all_open_flags)} ({crit_count} Critical, {high_count} High). "
            f"Status updated to '{recommended_status.value}'."
        ),
        details={
            "overall_compliance_score": overall_score,
            "recommended_status": recommended_status.value,
            "new_flags_added": len(new_flags),
            "total_open_flags": len(all_open_flags),
            "rectification_steps_count": len(rectification_steps),
        },
    )

    return {
        "application_id": application.id,
        "application_number": application.application_number,
        "academic_year": application.academic_year,
        "category": application.category.value,
        "status": application.status.value,
        "overall_compliance_score": overall_score,
        "score_breakdown": {
            "checklist_completeness_pct": completeness_score,
            "authority_verification_pct": verification_score,
            "data_consistency_and_safety_pct": max(0.0, 100.0 - penalty),
        },
        "checklist_status": checklist_item_details,
        "flag_summary": {
            "total": len(all_open_flags),
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "open_flags": all_open_flags,
        "rectification_steps": rectification_steps,
        "advisory_notes": validation_summary["recommended_decision"],
        "validated_at": now,
    }
