import json
from typing import Any, Dict, List, Optional
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from app.config import settings
from app.models.enums import DocumentType, FlagCategory, FlagSeverity


# --- Structured Output Schemas for Google Gemini 2.5 Flash (PRD §4.1, §4.2, §4.4, §8) ---

class GeminiExtractedFields(BaseModel):
    institution_name: Optional[str] = Field(
        default=None, description="Full name of the technical institution"
    )
    aicte_permanent_id: Optional[str] = Field(
        default=None, description="AICTE Permanent ID (e.g., 1-4928173650)"
    )
    certificate_number: Optional[str] = Field(
        default=None, description="Certificate number or Unique Reference Number (URN)"
    )
    eoa_reference_number: Optional[str] = Field(
        default=None, description="Previous Extension of Approval (EoA) file reference number"
    )
    stamp_paper_number: Optional[str] = Field(
        default=None, description="Non-judicial stamp paper serial number for affidavits"
    )
    issuing_authority: Optional[str] = Field(
        default=None, description="Name of the government or statutory issuing authority"
    )
    issue_date: Optional[str] = Field(
        default=None, description="Document issue date normalized to YYYY-MM-DD if possible"
    )
    expiry_date: Optional[str] = Field(
        default=None, description="Document expiry/validity date normalized to YYYY-MM-DD if possible"
    )
    deponent_name: Optional[str] = Field(
        default=None, description="Name and designation of the deponent/signatory on an affidavit"
    )
    approved_intake_total: Optional[int] = Field(
        default=None, description="Total student intake mentioned in the document"
    )
    building_area_sqm: Optional[float] = Field(
        default=None, description="Building or built-up area in square meters (sqm)"
    )
    built_up_area_sqm: Optional[float] = Field(
        default=None, description="Total built-up area in square meters (sqm)"
    )
    land_area_acres: Optional[float] = Field(
        default=None, description="Total campus land area in acres"
    )
    classrooms_count: Optional[int] = Field(
        default=None, description="Number of classrooms found in infrastructure evidence/floor plan"
    )
    min_classroom_area_sqm: Optional[float] = Field(
        default=None, description="Smallest classroom area in square meters observed on floor plan"
    )
    laboratories_count: Optional[int] = Field(
        default=None, description="Number of laboratories found in infrastructure evidence/floor plan"
    )
    min_laboratory_area_sqm: Optional[float] = Field(
        default=None, description="Smallest laboratory area in square meters observed on floor plan"
    )
    barrier_free_environment: Optional[bool] = Field(
        default=None,
        description="Whether ramps, lifts, and barrier-free washrooms for PwD are present",
    )
    digital_signature_or_qr_detected: Optional[bool] = Field(
        default=None,
        description="Whether a digital signature block, official seal, or QR verification code is visible",
    )


class GeminiExplainableFlag(BaseModel):
    flag_category: str = Field(
        description=(
            "One of: INCOMPLETE_FIELD, EXPIRED_DOCUMENT, CROSS_DOC_INCONSISTENCY, "
            "POTENTIAL_FORGERY_OR_ALTERATION, INFRASTRUCTURE_DISCREPANCY"
        )
    )
    severity: str = Field(description="One of: LOW, MEDIUM, HIGH, CRITICAL")
    field_name: str = Field(
        description="Name of the specific field, clause, or infrastructure item flagged"
    )
    reason: str = Field(
        description="Clear, explainable statement describing why this issue was flagged"
    )
    evidence_snippet: str = Field(
        description="Exact quote, value comparison, or visual observation from the document supporting the flag"
    )
    page_number: int = Field(
        default=1, description="Page number (1-indexed) where the issue was observed"
    )


class GeminiDocumentAnalysisResult(BaseModel):
    document_summary: str = Field(
        description="Brief 1-2 sentence summary of the uploaded document and its purpose"
    )
    authenticity_confidence_score: float = Field(
        description="Confidence score between 0.0 (highly suspicious) and 1.0 (authentic & consistent)"
    )
    extracted_fields: GeminiExtractedFields
    explainable_flags: List[GeminiExplainableFlag] = Field(default_factory=list)
    infrastructure_observations: List[str] = Field(
        default_factory=list,
        description="Advisory observations on floor plans, classrooms, labs, or safety facilities",
    )
    advisory_recommendation: str = Field(
        description="Decision-support recommendation for the AICTE Scrutiny Official (human-in-the-loop)"
    )


def _normalize_flag_category(raw_cat: str) -> FlagCategory:
    mapping = {
        "MISSING_DOCUMENT": FlagCategory.MISSING_DOCUMENT,
        "INCOMPLETE_FIELD": FlagCategory.INCOMPLETE_FIELD,
        "EXPIRED_DOCUMENT": FlagCategory.EXPIRED_DOCUMENT,
        "CROSS_DOC_INCONSISTENCY": FlagCategory.CROSS_DOC_INCONSISTENCY,
        "POTENTIAL_FORGERY_OR_ALTERATION": FlagCategory.POTENTIAL_FORGERY_OR_ALTERATION,
        "DUPLICATE_SUBMISSION": FlagCategory.DUPLICATE_SUBMISSION,
        "AUTHORITY_VERIFICATION_FAILURE": FlagCategory.AUTHORITY_VERIFICATION_FAILURE,
        "INFRASTRUCTURE_DISCREPANCY": FlagCategory.INFRASTRUCTURE_DISCREPANCY,
    }
    return mapping.get((raw_cat or "").upper().strip(), FlagCategory.CROSS_DOC_INCONSISTENCY)


def _normalize_flag_severity(raw_sev: str) -> FlagSeverity:
    mapping = {
        "LOW": FlagSeverity.LOW,
        "MEDIUM": FlagSeverity.MEDIUM,
        "HIGH": FlagSeverity.HIGH,
        "CRITICAL": FlagSeverity.CRITICAL,
    }
    return mapping.get((raw_sev or "").upper().strip(), FlagSeverity.MEDIUM)


def analyze_document_with_gemini(
    *,
    file_bytes: bytes,
    mime_type: str,
    document_type: DocumentType,
    raw_ocr_text: str,
    pdf_metadata: Dict[str, Any],
    baseline_extracted_fields: Dict[str, Any],
    institution_profile: Dict[str, Any],
    historical_records: Dict[str, Any],
    rule_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Runs multimodal AI validation using Google Gemini 2.5 Flash with Structured Outputs.
    - Extracts structured fields from PDFs, scanned certificates, and floor plans/photos.
    - Cross-verifies document claims against authorized AICTE historical records.
    - Evaluates infrastructure evidence against Approval Process Handbook thresholds.
    - Produces explainable flags with evidence snippets (PRD §4.1, §4.2, §4.4, §5).

    If `GEMINI_API_KEY` is not yet configured in `.env` (or if offline), automatically falls
    back to an intelligent local semantic analyzer returning the exact same schema so demos
    work out-of-the-box.
    """
    api_key = (settings.GEMINI_API_KEY or "").strip()
    has_live_key = bool(api_key and api_key != "your_gemini_api_key_here")

    if has_live_key:
        try:
            client = genai.Client(api_key=api_key)
            prompt = _build_gemini_prompt(
                document_type=document_type,
                raw_ocr_text=raw_ocr_text,
                pdf_metadata=pdf_metadata,
                baseline_extracted_fields=baseline_extracted_fields,
                institution_profile=institution_profile,
                historical_records=historical_records,
                rule_config=rule_config or {},
            )

            contents: List[Any] = [prompt]
            if file_bytes and mime_type in (
                "application/pdf",
                "image/png",
                "image/jpeg",
                "image/webp",
            ):
                contents.append(
                    types.Part.from_bytes(data=file_bytes, mime_type=mime_type)
                )

            response = client.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=contents,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                    response_schema=GeminiDocumentAnalysisResult,
                ),
            )

            parsed: GeminiDocumentAnalysisResult = response.parsed or GeminiDocumentAnalysisResult.model_validate_json(
                response.text
            )
            return _format_analysis_output(parsed, provider=f"google-genai ({settings.GEMINI_MODEL})")
        except Exception as exc:
            # Graceful fallback if network/quota/key error occurs during demo
            fallback_result = _run_local_semantic_fallback(
                document_type=document_type,
                raw_ocr_text=raw_ocr_text,
                pdf_metadata=pdf_metadata,
                baseline_extracted_fields=baseline_extracted_fields,
                institution_profile=institution_profile,
                historical_records=historical_records,
                rule_config=rule_config or {},
            )
            output = _format_analysis_output(
                fallback_result,
                provider=f"local-semantic-fallback (Gemini API error: {str(exc)[:120]})",
            )
            return output

    # No live GEMINI_API_KEY configured yet -> run local semantic & infrastructure analyzer
    fallback_result = _run_local_semantic_fallback(
        document_type=document_type,
        raw_ocr_text=raw_ocr_text,
        pdf_metadata=pdf_metadata,
        baseline_extracted_fields=baseline_extracted_fields,
        institution_profile=institution_profile,
        historical_records=historical_records,
        rule_config=rule_config or {},
    )
    return _format_analysis_output(
        fallback_result,
        provider="local-semantic-fallback (set GEMINI_API_KEY in .env for live Gemini 2.5 Flash)",
    )


def _build_gemini_prompt(
    *,
    document_type: DocumentType,
    raw_ocr_text: str,
    pdf_metadata: Dict[str, Any],
    baseline_extracted_fields: Dict[str, Any],
    institution_profile: Dict[str, Any],
    historical_records: Dict[str, Any],
    rule_config: Dict[str, Any],
) -> str:
    return f"""You are an AI Regulatory Scrutiny Assistant for the All India Council for Technical Education (AICTE) under the Approval Process Handbook (Project SIH26261).
Your role is strictly decision-support: extract structured fields from the attached institutional document, cross-verify consistency against historical AICTE records, check infrastructure compliance thresholds, and generate explainable flags supported by exact evidence.

1. UPLOADED DOCUMENT CATEGORY:
{document_type.value}

2. INSTITUTION PROFILE & HISTORICAL AICTE BASELINE RECORDS:
Institution Profile: {json.dumps(institution_profile, indent=2)}
Historical AICTE Records: {json.dumps(historical_records, indent=2)}

3. CONFIGURABLE HANDBOOK RULE & INFRASTRUCTURE THRESHOLDS:
{json.dumps(rule_config, indent=2)}

4. PYMUPDF OCR TEXT & PDF METADATA DIAGNOSTICS:
PDF Metadata: {json.dumps(pdf_metadata, indent=2)}
Baseline Regex Extracted Fields: {json.dumps(baseline_extracted_fields, indent=2)}
Raw OCR Text:
\"\"\"
{raw_ocr_text[:12000]}
\"\"\"

INSTRUCTIONS:
- Extract all relevant fields into `extracted_fields`. Normalize dates to YYYY-MM-DD where possible.
- Compare extracted values (e.g., `institution_name`, `aicte_permanent_id`, `approved_intake_total`, `built_up_area_sqm`, `eoa_reference_number`) against the Institution Profile and Historical AICTE Records. If there is a mismatch (e.g., document claims intake of 600 while historical approved intake is 420, or built-up area differs significantly), emit a `CROSS_DOC_INCONSISTENCY` flag in `explainable_flags` citing both values.
- If the document is `INFRASTRUCTURE_EVIDENCE` or `BUILDING_PLAN_CERTIFICATE`, check classroom area, laboratory area, built-up area, and barrier-free environment against `infrastructure_thresholds` in the rule config. Emit `INFRASTRUCTURE_DISCREPANCY` flags for any shortfall.
- Look for any semantic anomalies (e.g., expiry date before issue date, conflicting figures within the same text, suspicious alterations) and emit `POTENTIAL_FORGERY_OR_ALTERATION` flags with exact quotes in `evidence_snippet`.
- Every flag MUST include a clear `reason` and specific `evidence_snippet`.
"""


def _run_local_semantic_fallback(
    *,
    document_type: DocumentType,
    raw_ocr_text: str,
    pdf_metadata: Dict[str, Any],
    baseline_extracted_fields: Dict[str, Any],
    institution_profile: Dict[str, Any],
    historical_records: Dict[str, Any],
    rule_config: Dict[str, Any],
) -> GeminiDocumentAnalysisResult:
    """
    Deterministic semantic & infrastructure compliance analyzer that produces the exact
    `GeminiDocumentAnalysisResult` structured output when `GEMINI_API_KEY` is not set.
    """
    import re

    fields_dict: Dict[str, Any] = dict(baseline_extracted_fields)
    text_lower = (raw_ocr_text or "").lower()

    # Additional semantic extraction for infrastructure / floor plans / digital signatures
    classrooms_match = re.search(r"classrooms?\s*(?:count|total)?\s*[:\-]?\s*(\d+)", raw_ocr_text, re.IGNORECASE)
    if classrooms_match:
        fields_dict["classrooms_count"] = int(classrooms_match.group(1))

    min_cr_match = re.search(
        r"(?:minimum|smallest|standard)?\s*classroom\s*area\s*[:\-]?\s*([\d.]+)\s*(?:sq\.?\s*m|sqm)?",
        raw_ocr_text,
        re.IGNORECASE,
    )
    if min_cr_match:
        fields_dict["min_classroom_area_sqm"] = float(min_cr_match.group(1))

    labs_match = re.search(r"laborator(?:y|ies)\s*(?:count|total)?\s*[:\-]?\s*(\d+)", raw_ocr_text, re.IGNORECASE)
    if labs_match:
        fields_dict["laboratories_count"] = int(labs_match.group(1))

    min_lab_match = re.search(
        r"(?:minimum|smallest|standard)?\s*laboratory\s*area\s*[:\-]?\s*([\d.]+)\s*(?:sq\.?\s*m|sqm)?",
        raw_ocr_text,
        re.IGNORECASE,
    )
    if min_lab_match:
        fields_dict["min_laboratory_area_sqm"] = float(min_lab_match.group(1))

    if "barrier-free" in text_lower or "barrier free" in text_lower or "ramp" in text_lower:
        if any(neg in text_lower for neg in ["not available", "absent", "no ramp", "non-compliant", "barrier-free: no"]):
            fields_dict["barrier_free_environment"] = False
        else:
            fields_dict["barrier_free_environment"] = True

    fields_dict["digital_signature_or_qr_detected"] = any(
        kw in text_lower for kw in ["digitally signed", "qr code", "signature valid", "e-sign"]
    )

    extracted_model = GeminiExtractedFields(
        **{k: v for k, v in fields_dict.items() if k in GeminiExtractedFields.model_fields}
    )

    flags: List[GeminiExplainableFlag] = []
    infra_observations: List[str] = []

    # 1. Cross-Document & Historical AICTE Record Consistency Checks (PRD §4.1 & §4.2)
    hist_intake = historical_records.get("approved_intake_total")
    if extracted_model.approved_intake_total is not None and hist_intake is not None:
        if extracted_model.approved_intake_total != int(hist_intake):
            flags.append(
                GeminiExplainableFlag(
                    flag_category=FlagCategory.CROSS_DOC_INCONSISTENCY.value,
                    severity=FlagSeverity.HIGH.value,
                    field_name="approved_intake_total",
                    reason=(
                        f"Approved intake in uploaded {document_type.value} ({extracted_model.approved_intake_total}) "
                        f"does not match authorized AICTE historical record ({hist_intake})."
                    ),
                    evidence_snippet=(
                        f"Document states 'Approved Intake: {extracted_model.approved_intake_total}' vs. "
                        f"AICTE Historical Record: {hist_intake}"
                    ),
                    page_number=1,
                )
            )

    hist_area = historical_records.get("built_up_area_sqm")
    doc_area = extracted_model.built_up_area_sqm or extracted_model.building_area_sqm
    if doc_area is not None and hist_area is not None:
        if abs(float(doc_area) - float(hist_area)) > 50:
            flags.append(
                GeminiExplainableFlag(
                    flag_category=FlagCategory.CROSS_DOC_INCONSISTENCY.value,
                    severity=FlagSeverity.HIGH.value,
                    field_name="built_up_area_sqm",
                    reason=(
                        f"Built-up/building area in {document_type.value} ({doc_area} sqm) "
                        f"disagrees with historical AICTE record ({hist_area} sqm)."
                    ),
                    evidence_snippet=(
                        f"Document Area: {doc_area} sqm | Historical AICTE Built-up Area: {hist_area} sqm"
                    ),
                    page_number=1,
                )
            )

    expected_inst_name = institution_profile.get("name")
    if extracted_model.institution_name and expected_inst_name:
        if extracted_model.institution_name.strip().lower() != expected_inst_name.strip().lower():
            flags.append(
                GeminiExplainableFlag(
                    flag_category=FlagCategory.CROSS_DOC_INCONSISTENCY.value,
                    severity=FlagSeverity.HIGH.value,
                    field_name="institution_name",
                    reason=(
                        f"Institution name on document ('{extracted_model.institution_name}') "
                        f"does not match registered applicant institution ('{expected_inst_name}')."
                    ),
                    evidence_snippet=f"Extracted: '{extracted_model.institution_name}' | Expected: '{expected_inst_name}'",
                    page_number=1,
                )
            )

    # 2. Infrastructure Compliance Assistance Checks (PRD §4.4)
    thresholds = (rule_config or {}).get("infrastructure_thresholds") or {}
    if document_type in (DocumentType.INFRASTRUCTURE_EVIDENCE, DocumentType.BUILDING_PLAN_CERTIFICATE) or thresholds:
        min_req_cr = thresholds.get("min_classroom_area_sqm", 66)
        if extracted_model.min_classroom_area_sqm is not None:
            infra_observations.append(
                f"Observed Classroom Area: {extracted_model.min_classroom_area_sqm} sqm (Handbook minimum: {min_req_cr} sqm)"
            )
            if extracted_model.min_classroom_area_sqm < float(min_req_cr):
                flags.append(
                    GeminiExplainableFlag(
                        flag_category=FlagCategory.INFRASTRUCTURE_DISCREPANCY.value,
                        severity=FlagSeverity.HIGH.value,
                        field_name="min_classroom_area_sqm",
                        reason=(
                            f"Classroom area on floor plan ({extracted_model.min_classroom_area_sqm} sqm) is below "
                            f"the AICTE Approval Process Handbook minimum requirement of {min_req_cr} sqm."
                        ),
                        evidence_snippet=(
                            f"Floor Plan Classroom Area: {extracted_model.min_classroom_area_sqm} sqm < Required {min_req_cr} sqm"
                        ),
                        page_number=1,
                    )
                )

        min_req_lab = thresholds.get("min_laboratory_area_sqm", 66)
        if extracted_model.min_laboratory_area_sqm is not None:
            infra_observations.append(
                f"Observed Laboratory Area: {extracted_model.min_laboratory_area_sqm} sqm (Handbook minimum: {min_req_lab} sqm)"
            )
            if extracted_model.min_laboratory_area_sqm < float(min_req_lab):
                flags.append(
                    GeminiExplainableFlag(
                        flag_category=FlagCategory.INFRASTRUCTURE_DISCREPANCY.value,
                        severity=FlagSeverity.HIGH.value,
                        field_name="min_laboratory_area_sqm",
                        reason=(
                            f"Laboratory area ({extracted_model.min_laboratory_area_sqm} sqm) is below "
                            f"the AICTE Approval Process Handbook minimum of {min_req_lab} sqm."
                        ),
                        evidence_snippet=(
                            f"Floor Plan Laboratory Area: {extracted_model.min_laboratory_area_sqm} sqm < Required {min_req_lab} sqm"
                        ),
                        page_number=1,
                    )
                )

        if thresholds.get("barrier_free_environment_required") and extracted_model.barrier_free_environment is False:
            infra_observations.append("Barrier-free environment (ramps/lifts/PwD washrooms) reported as missing/non-compliant.")
            flags.append(
                GeminiExplainableFlag(
                    flag_category=FlagCategory.INFRASTRUCTURE_DISCREPANCY.value,
                    severity=FlagSeverity.MEDIUM.value,
                    field_name="barrier_free_environment",
                    reason=(
                        "Barrier-free environment facilities (ramps/elevators for PwD) required by the "
                        "AICTE Approval Process Handbook are missing or marked non-compliant in the evidence."
                    ),
                    evidence_snippet="Barrier-Free / Ramp Compliance: Not Available / Non-Compliant",
                    page_number=1,
                )
            )

    # Calculate advisory confidence score
    penalty = 0.2 * len(flags) + (0.25 if (pdf_metadata.get("distinct_fonts_total") or 1) >= 5 else 0.0)
    confidence = max(0.15, round(1.0 - penalty, 2))

    recommendation = (
        "All extracted parameters align with AICTE historical records and handbook norms. Ready for official scrutiny."
        if not flags
        else f"Advisory Alert: {len(flags)} semantic/compliance discrepancy flag(s) identified. Route to AICTE Scrutiny Officer for human-in-the-loop verification."
    )

    return GeminiDocumentAnalysisResult(
        document_summary=(
            f"AI structured analysis of {document_type.value} for "
            f"{extracted_model.institution_name or institution_profile.get('name', 'Institution')}."
        ),
        authenticity_confidence_score=confidence,
        extracted_fields=extracted_model,
        explainable_flags=flags,
        infrastructure_observations=infra_observations,
        advisory_recommendation=recommendation,
    )


def _format_analysis_output(
    result: GeminiDocumentAnalysisResult,
    provider: str,
) -> Dict[str, Any]:
    cleaned_fields = {
        k: v
        for k, v in result.extracted_fields.model_dump().items()
        if v is not None
    }
    normalized_flags = [
        {
            "flag_category": _normalize_flag_category(f.flag_category),
            "severity": _normalize_flag_severity(f.severity),
            "field_name": f.field_name,
            "reason": f.reason,
            "evidence_snippet": f.evidence_snippet,
            "page_number": f.page_number,
        }
        for f in result.explainable_flags
    ]
    return {
        "ai_provider": provider,
        "document_summary": result.document_summary,
        "authenticity_confidence_score": result.authenticity_confidence_score,
        "extracted_fields": cleaned_fields,
        "explainable_flags": normalized_flags,
        "infrastructure_observations": result.infrastructure_observations,
        "advisory_recommendation": result.advisory_recommendation,
    }
