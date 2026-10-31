import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import fitz  # PyMuPDF

from app.models.enums import FlagCategory, FlagSeverity

# Known consumer PDF/image editing & manipulation tools that warrant a preliminary tampering flag
SUSPICIOUS_PRODUCERS_AND_CREATORS = [
    "photoshop",
    "illustrator",
    "gimp",
    "canva",
    "ilovepdf",
    "sejda",
    "smallpdf",
    "pdfescape",
    "paint.net",
    "coreldraw",
    "inkscape",
    "nitro pro",
    "foxit phantompdf",
]


def compute_sha256(file_bytes: bytes) -> str:
    """Compute SHA-256 cryptographic digest to detect duplicate document submissions."""
    return hashlib.sha256(file_bytes).hexdigest()


def _parse_pdf_date(pdf_date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse standard PDF date format (e.g. 'D:20261015093000+05'30'' or 'D:20261015093000Z')
    into a timezone-aware UTC datetime for comparison.
    """
    if not pdf_date_str or not isinstance(pdf_date_str, str):
        return None
    cleaned = pdf_date_str.strip()
    if cleaned.startswith("D:"):
        cleaned = cleaned[2:]

    # Extract basic YYYYMMDDHHMMSS prefix (up to 14 digits)
    digits_match = re.match(r"^(\d{8,14})", cleaned)
    if not digits_match:
        return None

    raw_digits = digits_match.group(1)
    try:
        if len(raw_digits) >= 14:
            dt = datetime.strptime(raw_digits[:14], "%Y%m%d%H%M%S")
        elif len(raw_digits) >= 12:
            dt = datetime.strptime(raw_digits[:12], "%Y%m%d%H%M")
        else:
            dt = datetime.strptime(raw_digits[:8], "%Y%m%d")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def extract_baseline_fields(raw_text: str) -> Dict[str, Any]:
    """
    Deterministic regex-based extraction of common AICTE document fields from raw OCR text.
    Provides immediate structured data before/alongside Google Gemini LLM extraction.
    """
    extracted: Dict[str, Any] = {}
    if not raw_text:
        return extracted

    # 1. AICTE Permanent ID (e.g., 1-4928173650)
    aicte_id_match = re.search(r"\b(1-\d{8,12})\b", raw_text)
    if aicte_id_match:
        extracted["aicte_permanent_id"] = aicte_id_match.group(1)

    # 2. EoA Reference Number (e.g., F.No. Western/1-4928173650/2025/EOA)
    eoa_ref_match = re.search(
        r"(F\.?\s*No\.?\s*[A-Za-z0-9/\-_]+/EOA)", raw_text, re.IGNORECASE
    )
    if eoa_ref_match:
        extracted["eoa_reference_number"] = eoa_ref_match.group(1).strip()

    # 3. Certificate / URN / Stamp Paper Number
    cert_match = re.search(
        r"(?:Certificate\s*(?:No|Number|URN)|URN|Stamp\s*Paper\s*(?:No|Number))\s*[:\-]?\s*([A-Z0-9/\-_]{5,30})",
        raw_text,
        re.IGNORECASE,
    )
    if cert_match:
        val = cert_match.group(1).strip()
        extracted["certificate_number"] = val
        extracted["stamp_paper_number"] = val

    # 4. Issue Date & Expiry Date (YYYY-MM-DD or DD/MM/YYYY or DD-MM-YYYY)
    issue_match = re.search(
        r"(?:Issue\s*Date|Date\s*of\s*Issue|Dated|Sworn\s*on)\s*[:\-]?\s*(\d{4}-\d{2}-\d{2}|\d{2}[/\-]\d{2}[/\-]\d{4})",
        raw_text,
        re.IGNORECASE,
    )
    if issue_match:
        extracted["issue_date"] = issue_match.group(1).strip()

    expiry_match = re.search(
        r"(?:Expiry\s*Date|Valid\s*(?:Upto|Until|Till)|Date\s*of\s*Expiry)\s*[:\-]?\s*(\d{4}-\d{2}-\d{2}|\d{2}[/\-]\d{2}[/\-]\d{4})",
        raw_text,
        re.IGNORECASE,
    )
    if expiry_match:
        extracted["expiry_date"] = expiry_match.group(1).strip()

    # 5. Institution Name
    inst_match = re.search(
        r"(?:Institution\s*Name|Name\s*of\s*(?:the\s*)?Institution|College\s*Name)\s*[:\-]\s*([^\n\r]+)",
        raw_text,
        re.IGNORECASE,
    )
    if inst_match:
        extracted["institution_name"] = inst_match.group(1).strip()

    # 6. Issuing Authority
    auth_match = re.search(
        r"(?:Issuing\s*Authority|Issued\s*By)\s*[:\-]\s*([^\n\r]+)",
        raw_text,
        re.IGNORECASE,
    )
    if auth_match:
        extracted["issuing_authority"] = auth_match.group(1).strip()

    # 7. Built-up / Building Area (sqm)
    area_match = re.search(
        r"(?:Built[\-\s]*up\s*Area|Building\s*Area)\s*[:\-]?\s*([\d,]+(?:\.\d+)?)\s*(?:sq\.?\s*m|sqm)?",
        raw_text,
        re.IGNORECASE,
    )
    if area_match:
        try:
            area_val = float(area_match.group(1).replace(",", ""))
            extracted["building_area_sqm"] = (
                int(area_val) if area_val.is_integer() else area_val
            )
            extracted["built_up_area_sqm"] = extracted["building_area_sqm"]
        except ValueError:
            pass

    # 8. Approved Intake Total
    intake_match = re.search(
        r"(?:Approved\s*Intake|Total\s*Intake)\s*[:\-]?\s*(\d{2,5})",
        raw_text,
        re.IGNORECASE,
    )
    if intake_match:
        extracted["approved_intake_total"] = int(intake_match.group(1))

    # 9. Deponent Name (for Affidavits)
    deponent_match = re.search(
        r"(?:Deponent\s*(?:Name)?|Signed\s*by\s*Principal)\s*[:\-]\s*([^\n\r]+)",
        raw_text,
        re.IGNORECASE,
    )
    if deponent_match:
        extracted["deponent_name"] = deponent_match.group(1).strip()

    return extracted


def extract_pdf_intelligence(
    file_bytes: bytes,
    filename: str,
) -> Tuple[str, Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]:
    """
    Uses PyMuPDF (fitz) to extract:
      1. Raw text across all pages
      2. Structural & forensic PDF metadata (fonts, dates, producer, page diagnostics)
      3. Deterministic key-value fields
      4. Explainable AI / forensic anomaly flags (PRD §4.1 & §4.2)
    """
    anomaly_flags: List[Dict[str, Any]] = []

    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
    except Exception as exc:
        return (
            "",
            {"error": f"Failed to parse PDF stream: {str(exc)}"},
            {},
            [
                {
                    "flag_category": FlagCategory.POTENTIAL_FORGERY_OR_ALTERATION,
                    "severity": FlagSeverity.HIGH,
                    "field_name": "file_format",
                    "reason": "Uploaded PDF file is corrupted or cannot be parsed by PyMuPDF.",
                    "evidence_snippet": f"Filename: {filename} | Parser error: {str(exc)}",
                    "page_number": None,
                }
            ],
        )

    raw_metadata = doc.metadata or {}
    page_count = len(doc)
    full_text_parts: List[str] = []
    page_diagnostics: List[Dict[str, Any]] = []
    all_fonts_set = set()

    for page_idx in range(page_count):
        page = doc[page_idx]
        page_num = page_idx + 1
        page_text = page.get_text("text") or ""
        full_text_parts.append(page_text)

        # Extract fonts and sizes from structural text dictionary
        text_dict = page.get_text("dict")
        page_fonts = set()
        page_font_sizes = set()
        for block in text_dict.get("blocks", []):
            if block.get("type") == 0:  # text block
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        font_name = span.get("font")
                        font_size = span.get("size")
                        if font_name:
                            page_fonts.add(font_name)
                            all_fonts_set.add(font_name)
                        if font_size:
                            page_font_sizes.add(round(float(font_size), 1))

        images_on_page = len(page.get_images(full=True))
        char_count = len(page_text.strip())

        page_diagnostics.append(
            {
                "page_number": page_num,
                "char_count": char_count,
                "fonts_detected": sorted(page_fonts),
                "font_sizes_detected": sorted(page_font_sizes),
                "image_count": images_on_page,
                "is_likely_scanned_image": char_count < 30 and images_on_page > 0,
            }
        )

        # Forensic Check 1: Excessive font variety on a single certificate page (indicative of spliced/pasted text)
        if len(page_fonts) >= 5:
            anomaly_flags.append(
                {
                    "flag_category": FlagCategory.POTENTIAL_FORGERY_OR_ALTERATION,
                    "severity": FlagSeverity.MEDIUM,
                    "field_name": "pdf_fonts",
                    "reason": (
                        f"Mismatched font families detected on page {page_num} ({len(page_fonts)} distinct fonts). "
                        "Official certificates typically use 1–3 consistent font families; mixed fonts may indicate text splicing."
                    ),
                    "evidence_snippet": f"Fonts on Page {page_num}: {', '.join(sorted(page_fonts))}",
                    "page_number": page_num,
                }
            )

    doc.close()

    raw_text = "\n\n".join(full_text_parts).strip()

    # Forensic Check 2: Suspicious PDF Creator / Producer software
    creator = (raw_metadata.get("creator") or "").strip()
    producer = (raw_metadata.get("producer") or "").strip()
    combined_software = f"{creator} {producer}".lower()

    matched_tools = [
        tool for tool in SUSPICIOUS_PRODUCERS_AND_CREATORS if tool in combined_software
    ]
    if matched_tools:
        anomaly_flags.append(
            {
                "flag_category": FlagCategory.POTENTIAL_FORGERY_OR_ALTERATION,
                "severity": FlagSeverity.HIGH,
                "field_name": "pdf_metadata.producer",
                "reason": (
                    f"Document metadata indicates processing by external editing tool ({', '.join(matched_tools)}). "
                    "Requires manual verification against original issuing authority."
                ),
                "evidence_snippet": f"Creator: '{creator}' | Producer: '{producer}'",
                "page_number": 1,
            }
        )

    # Forensic Check 3: Modification timestamp significantly later than creation timestamp
    creation_raw = raw_metadata.get("creationDate")
    mod_raw = raw_metadata.get("modDate")
    created_dt = _parse_pdf_date(creation_raw)
    mod_dt = _parse_pdf_date(mod_raw)

    if created_dt and mod_dt:
        delta_seconds = (mod_dt - created_dt).total_seconds()
        if delta_seconds > 86400:  # Modified more than 24 hours after initial PDF creation
            days_diff = round(delta_seconds / 86400, 1)
            anomaly_flags.append(
                {
                    "flag_category": FlagCategory.POTENTIAL_FORGERY_OR_ALTERATION,
                    "severity": FlagSeverity.MEDIUM,
                    "field_name": "pdf_metadata.modDate",
                    "reason": (
                        f"PDF modification timestamp is {days_diff} days after initial creation timestamp, "
                        "indicating post-issuance editing or re-saving."
                    ),
                    "evidence_snippet": (
                        f"creationDate: {created_dt.isoformat()} | modDate: {mod_dt.isoformat()}"
                    ),
                    "page_number": 1,
                }
            )
        elif delta_seconds < -60:
            anomaly_flags.append(
                {
                    "flag_category": FlagCategory.POTENTIAL_FORGERY_OR_ALTERATION,
                    "severity": FlagSeverity.HIGH,
                    "field_name": "pdf_metadata.timestamps",
                    "reason": "Irregular metadata dates: modification timestamp precedes creation timestamp.",
                    "evidence_snippet": (
                        f"creationDate: {created_dt.isoformat()} | modDate: {mod_dt.isoformat()}"
                    ),
                    "page_number": 1,
                }
            )

    # Forensic Check 4: Empty or image-only PDF without extractable text
    if len(raw_text) < 20:
        anomaly_flags.append(
            {
                "flag_category": FlagCategory.INCOMPLETE_FIELD,
                "severity": FlagSeverity.MEDIUM,
                "field_name": "raw_ocr_text",
                "reason": (
                    "Document contains minimal or no machine-readable text (likely an unindexed scan or blank file). "
                    "Flagged for Vision OCR / manual inspection."
                ),
                "evidence_snippet": f"Total extracted characters across {page_count} page(s): {len(raw_text)}",
                "page_number": 1,
            }
        )

    pdf_metadata_summary = {
        "page_count": page_count,
        "title": raw_metadata.get("title"),
        "author": raw_metadata.get("author"),
        "creator": creator,
        "producer": producer,
        "creationDate": creation_raw,
        "modDate": mod_raw,
        "distinct_fonts_total": len(all_fonts_set),
        "all_fonts": sorted(all_fonts_set),
        "pages": page_diagnostics,
    }

    extracted_fields = extract_baseline_fields(raw_text)

    return raw_text, pdf_metadata_summary, extracted_fields, anomaly_flags
