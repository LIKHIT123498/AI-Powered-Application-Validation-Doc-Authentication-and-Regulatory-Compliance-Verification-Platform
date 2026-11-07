from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlmodel import Session, select

from app.models.enums import (
    DocumentType,
    FlagCategory,
    FlagSeverity,
    VerificationStatus,
)
from app.models.models import Application, Document, Institution, ValidationFlag
from app.services.audit_service import log_audit_event

# -------------------------------------------------------------------------
# Simulated / Authorized Issuing Authority Registries (PRD §4.3)
# In production, these integrate with state e-District APIs, DigiLocker,
# Council of Architecture (COA) API, and AICTE Central Repositories.
# -------------------------------------------------------------------------

AUTHORIZED_REGISTRIES: Dict[str, Dict[str, Any]] = {
    # 1. State Fire & Emergency Services Portal (e.g. Maharashtra Fire Services)
    "MH-FIRE-PUNE-2026-88412": {
        "registry_name": "Maharashtra Fire & Life Safety e-Services Portal (Directorate of Fire Services)",
        "document_type": DocumentType.FIRE_SAFETY_CERTIFICATE,
        "urn": "MH-FIRE-PUNE-2026-88412",
        "institution_name": "Apex Institute of Engineering and Technology",
        "aicte_permanent_id": "1-4928173650",
        "issuing_authority": "Directorate of Maharashtra Fire Services, Pune Division",
        "issue_date": "2026-06-15",
        "expiry_date": "2027-06-14",
        "building_area_sqm": 14800,
        "status": "ACTIVE",
        "digital_signature_verified": True,
        "verified_by_officer": "Chief Fire Officer, Pune Metropolitan Region",
    },
    # Sample expired fire certificate for negative testing
    "MH-FIRE-PUNE-2024-11029": {
        "registry_name": "Maharashtra Fire & Life Safety e-Services Portal",
        "document_type": DocumentType.FIRE_SAFETY_CERTIFICATE,
        "urn": "MH-FIRE-PUNE-2024-11029",
        "institution_name": "Apex Institute of Engineering and Technology",
        "aicte_permanent_id": "1-4928173650",
        "issuing_authority": "Directorate of Maharashtra Fire Services",
        "issue_date": "2024-05-01",
        "expiry_date": "2025-04-30",
        "building_area_sqm": 14800,
        "status": "EXPIRED",
        "digital_signature_verified": True,
    },
    # 2. National e-Stamping & Non-Judicial Registry (Affidavits)
    "MH-STAMP-9920184": {
        "registry_name": "National e-Stamping Verification Portal (SHCIL / State Inspector General)",
        "document_type": DocumentType.AFFIDAVIT,
        "urn": "MH-STAMP-9920184",
        "institution_name": "Apex Institute of Engineering and Technology",
        "aicte_permanent_id": "1-4928173650",
        "deponent_name": "Dr. Rajesh Kulkarni",
        "issuing_authority": "Superintendent of Stamps, Govt. of Maharashtra",
        "issue_date": "2026-08-01",
        "status": "ACTIVE",
        "approved_intake_total": 420,  # Registry baseline approved intake is 420
    },
    # 3. AICTE Central Approval Database (Previous EoA Letters)
    "F.No. Western/1-4928173650/2025/EOA": {
        "registry_name": "AICTE Central Approval Process Database (National Portal)",
        "document_type": DocumentType.PREVIOUS_EOA_LETTER,
        "urn": "F.No. Western/1-4928173650/2025/EOA",
        "institution_name": "Apex Institute of Engineering and Technology",
        "aicte_permanent_id": "1-4928173650",
        "academic_year": "2025-26",
        "approved_intake_total": 420,
        "status": "ACTIVE",
        "issuing_authority": "All India Council for Technical Education, New Delhi",
    },
    # 4. Council of Architecture / Municipal Building Plan Registry
    "CA/2018/90421": {
        "registry_name": "Council of Architecture (COA) National Registry / Pune Municipal Corp.",
        "document_type": DocumentType.BUILDING_PLAN_CERTIFICATE,
        "urn": "CA/2018/90421",
        "institution_name": "Apex Institute of Engineering and Technology",
        "aicte_permanent_id": "1-4928173650",
        "issuing_authority": "Certified Chartered Architect (COA Reg. CA/2018/90421)",
        "registered_built_up_area_sqm": 14800,
        "license_status": "ACTIVE",
    },
}


def verify_document_with_issuing_authority(
    session: Session,
    document: Document,
    actor_user_id: Optional[int] = None,
) -> Tuple[VerificationStatus, Dict[str, Any], List[ValidationFlag]]:
    """
    Executes automated issuing-authority verification workflow (PRD §4.3):
    1. Looks up URN/reference ID from document attributes or OCR/Gemini extracted fields.
    2. Queries the official issuing-authority API/digital repository.
    3. Cross-compares submitted details against authorized source records.
    4. Logs status (VERIFIED, MISMATCH, EXPIRED, SOURCE_UNAVAILABLE, MANUAL_REVIEW_REQUIRED).
    5. Creates explainable ValidationFlag records for any discrepancy with evidence.
    """
    now = datetime.now(timezone.utc)
    extracted = document.extracted_fields or {}

    # Identify lookup key
    urn_candidate = (
        document.document_urn_or_id
        or extracted.get("certificate_number")
        or extracted.get("eoa_reference_number")
        or extracted.get("stamp_paper_number")
    )

    if not urn_candidate:
        # Fallback to manual review if URN or Certificate Number cannot be detected
        status_result = VerificationStatus.MANUAL_REVIEW_REQUIRED
        details = {
            "source": "Automated Authority Verification Engine",
            "urn_queried": None,
            "timestamp": now.isoformat(),
            "reason": "Document does not contain a detectable Unique Reference Number (URN), Certificate Number, or QR verification code.",
            "action_taken": "Routed to AICTE Official for manual scrutiny.",
        }
        document.verification_status = status_result
        document.verification_details = details
        session.add(document)
        session.commit()
        return status_result, details, []

    # Clean URN for query
    clean_urn = urn_candidate.strip()
    registry_entry = AUTHORIZED_REGISTRIES.get(clean_urn)

    # In case of partial match or whitespace difference
    if not registry_entry:
        for reg_key, reg_val in AUTHORIZED_REGISTRIES.items():
            if reg_key.lower() == clean_urn.lower() or reg_key in clean_urn:
                registry_entry = reg_val
                break

    created_flags: List[ValidationFlag] = []

    if not registry_entry:
        # Source not found or API unavailable
        status_result = VerificationStatus.SOURCE_UNAVAILABLE
        details = {
            "source": "External Issuing Authority Gateway",
            "urn_queried": clean_urn,
            "timestamp": now.isoformat(),
            "registry_name": "National Digital Repositories / State Portals",
            "result": "URN not found in authorized issuer database or issuer API unavailable.",
            "fallback": "Flagged for manual confirmation against original issuing authority.",
        }
        flag = ValidationFlag(
            application_id=document.application_id,
            document_id=document.id,
            flag_category=FlagCategory.AUTHORITY_VERIFICATION_FAILURE,
            severity=FlagSeverity.HIGH,
            field_name="document_urn_or_id",
            reason=(
                f"Document reference '{clean_urn}' could not be authenticated against the "
                "original issuing authority digital registry. Requires manual verification."
            ),
            evidence_snippet=f"URN Queried: {clean_urn} | Status: SOURCE_UNAVAILABLE",
            page_number=1,
        )
        session.add(flag)
        created_flags.append(flag)

    else:
        # Compare submitted details against authorized source
        mismatches: List[str] = []
        reg_name = registry_entry.get("registry_name", "Authorized Issuing Registry")

        # 1. Expiry check from registry
        reg_status = registry_entry.get("status")
        reg_expiry = registry_entry.get("expiry_date")
        if reg_status == "EXPIRED" or (reg_expiry and reg_expiry < now.strftime("%Y-%m-%d")):
            status_result = VerificationStatus.EXPIRED
            mismatches.append(f"Certificate is marked EXPIRED in official registry (Valid until {reg_expiry}).")
            flag = ValidationFlag(
                application_id=document.application_id,
                document_id=document.id,
                flag_category=FlagCategory.EXPIRED_DOCUMENT,
                severity=FlagSeverity.CRITICAL,
                field_name="expiry_date",
                reason=f"Official issuing authority registry ({reg_name}) confirms document expired on {reg_expiry}.",
                evidence_snippet=f"Registry Entry: {clean_urn} | Status: EXPIRED | Expiry: {reg_expiry}",
                page_number=1,
            )
            session.add(flag)
            created_flags.append(flag)

        # 2. Institution Name match check
        reg_inst_name = registry_entry.get("institution_name")
        doc_inst_name = extracted.get("institution_name")
        if reg_inst_name and doc_inst_name:
            if reg_inst_name.strip().lower() != doc_inst_name.strip().lower():
                mismatches.append(
                    f"Institution name mismatch: Document says '{doc_inst_name}' but registry has '{reg_inst_name}'."
                )

        # 3. Approved Intake / Value match check
        reg_intake = registry_entry.get("approved_intake_total")
        doc_intake = extracted.get("approved_intake_total")
        if reg_intake is not None and doc_intake is not None:
            if int(reg_intake) != int(doc_intake):
                mismatches.append(
                    f"Approved intake mismatch: Document states {doc_intake} while official registry record confirms {reg_intake}."
                )

        # 4. Building Area check
        reg_area = registry_entry.get("building_area_sqm") or registry_entry.get("registered_built_up_area_sqm")
        doc_area = extracted.get("building_area_sqm") or extracted.get("built_up_area_sqm")
        if reg_area is not None and doc_area is not None:
            if abs(float(reg_area) - float(doc_area)) > 50:
                mismatches.append(
                    f"Building area mismatch: Document specifies {doc_area} sqm but official registry record is {reg_area} sqm."
                )

        if mismatches:
            status_result = VerificationStatus.MISMATCH if reg_status != "EXPIRED" else VerificationStatus.EXPIRED
            for m in mismatches:
                flag = ValidationFlag(
                    application_id=document.application_id,
                    document_id=document.id,
                    flag_category=FlagCategory.AUTHORITY_VERIFICATION_FAILURE,
                    severity=FlagSeverity.HIGH,
                    field_name="issuing_authority_registry",
                    reason=f"Issuing Authority Verification Discrepancy ({reg_name}): {m}",
                    evidence_snippet=f"Official Source Record: {registry_entry}",
                    page_number=1,
                )
                session.add(flag)
                created_flags.append(flag)
        else:
            status_result = VerificationStatus.VERIFIED

        details = {
            "source": reg_name,
            "urn_queried": clean_urn,
            "timestamp": now.isoformat(),
            "status": status_result.value,
            "issuing_authority": registry_entry.get("issuing_authority"),
            "authorized_source_record": registry_entry,
            "discrepancies": mismatches,
            "digital_signature_verified": registry_entry.get("digital_signature_verified", False),
        }

    # Update document model
    document.verification_status = status_result
    document.issuing_authority = registry_entry.get("issuing_authority") if registry_entry else document.issuing_authority
    ver_details = dict(document.verification_details or {})
    ver_details["authority_verification"] = details
    document.verification_details = ver_details
    session.add(document)
    session.commit()
    session.refresh(document)

    for flg in created_flags:
        session.refresh(flg)

    # Log audit event
    log_audit_event(
        session,
        application_id=document.application_id,
        action_type="AUTHORITY_VERIFICATION_COMPLETED",
        entity_type="Document",
        entity_id=str(document.id),
        actor_role_override="ISSUING_AUTHORITY_GATEWAY",
        summary=(
            f"Issuing authority verification for Document #{document.id} ({document.document_type.value}) "
            f"completed with status '{status_result.value}'. URN: '{clean_urn}'."
        ),
        details=details,
    )

    return status_result, details, created_flags
