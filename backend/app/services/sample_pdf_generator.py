from pathlib import Path
from typing import Dict
import fitz  # PyMuPDF


def generate_demo_pdfs(output_dir: Path = Path("sample_docs")) -> Dict[str, str]:
    """
    Generates two realistic sample AICTE PDFs using PyMuPDF so you can immediately
    test Phase 2 Document Upload, OCR Extraction, and Forgery/Anomaly Detection:
      1. `valid_fire_safety_certificate.pdf` (Clean metadata, consistent font, complete fields)
      2. `tampered_affidavit_certificate.pdf` (Altered via 'Photoshop/iLovePDF', 5 mixed fonts, post-creation modDate)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate Valid Fire Safety Certificate
    valid_path = output_dir / "valid_fire_safety_certificate.pdf"
    doc_valid = fitz.open()
    page_v = doc_valid.new_page(width=595, height=842)  # A4

    valid_lines = [
        "DIRECTORATE OF MAHARASHTRA FIRE AND EMERGENCY SERVICES",
        "FIRE SAFETY COMPLIANCE CERTIFICATE (FORM-B)",
        "------------------------------------------------------------------------",
        "Certificate Number: MH-FIRE-PUNE-2026-88412",
        "Issuing Authority: Directorate of Maharashtra Fire Services, Pune Division",
        "Issue Date: 2026-06-15",
        "Expiry Date: 2027-06-14",
        "",
        "Institution Name: Apex Institute of Engineering and Technology",
        "AICTE Permanent ID: 1-4928173650",
        "Address: Plot No. 42, Knowledge Park, Hinjewadi Phase II, Pune - 411057",
        "Building Area: 14800 sqm",
        "",
        "CERTIFICATION STATEMENT:",
        "This is to certify that the multi-storeyed institutional building of",
        "Apex Institute of Engineering and Technology has been inspected on 2026-06-10",
        "and found to comply with the National Building Code (NBC) fire prevention",
        "and life safety norms for educational buildings.",
        "",
        "Digitally Signed By: Chief Fire Officer, Pune Metropolitan Region",
    ]

    y = 72
    for line in valid_lines:
        page_v.insert_text((54, y), line, fontsize=11, fontname="helv")
        y += 22

    doc_valid.set_metadata(
        {
            "title": "Fire Safety Certificate - Apex Institute",
            "author": "Directorate of Maharashtra Fire Services",
            "creator": "Maharashtra e-District Official Portal v4.2",
            "producer": "Government NIC PDF Signer",
            "creationDate": "D:20260615103000Z",
            "modDate": "D:20260615103005Z",
        }
    )
    doc_valid.save(str(valid_path))
    doc_valid.close()

    # 2. Generate Tampered / Altered Affidavit PDF (triggers forensic flags)
    tampered_path = output_dir / "tampered_affidavit_certificate.pdf"
    doc_tampered = fitz.open()
    page_t = doc_tampered.new_page(width=595, height=842)

    # Insert text using 5 different built-in fonts on the same page to simulate text splicing
    page_t.insert_text(
        (54, 72),
        "BEFORE THE ALL INDIA COUNCIL FOR TECHNICAL EDUCATION",
        fontsize=13,
        fontname="helv",
    )
    page_t.insert_text(
        (54, 100),
        "STANDARD AFFIDAVIT-2 ON NON-JUDICIAL STAMP PAPER",
        fontsize=12,
        fontname="tiro",  # Times-Roman
    )
    page_t.insert_text(
        (54, 140),
        "Stamp Paper Number: MH-STAMP-9920184",
        fontsize=11,
        fontname="cour",  # Courier
    )
    page_t.insert_text(
        (54, 170),
        "Institution Name: Apex Institute of Engineering and Technology",
        fontsize=11,
        fontname="times-bold",
    )
    page_t.insert_text(
        (54, 200),
        "AICTE Permanent ID: 1-4928173650",
        fontsize=11,
        fontname="helvetica-bold",
    )
    # Spliced date and intake line in oblique font
    page_t.insert_text(
        (54, 230),
        "Issue Date: 2026-08-20",
        fontsize=12,
        fontname="helvetica-oblique",
    )
    page_t.insert_text(
        (54, 260),
        "Approved Intake: 600",
        fontsize=12,
        fontname="courier-bold",
    )
    page_t.insert_text(
        (54, 300),
        "I hereby solemnly affirm that our institution meets all AICTE norms.",
        fontsize=11,
        fontname="helv",
    )

    # Set suspicious creator/producer and a modDate 18 days after creationDate
    doc_tampered.set_metadata(
        {
            "title": "Affidavit-2 Scanned Edited",
            "author": "Unknown User",
            "creator": "Adobe Photoshop 2026",
            "producer": "iLovePDF / Canva PDF Editor",
            "creationDate": "D:20260801090000Z",
            "modDate": "D:20260819184500Z",
        }
    )
    doc_tampered.save(str(tampered_path))
    doc_tampered.close()

    return {
        "valid_pdf": str(valid_path.resolve()),
        "tampered_pdf": str(tampered_path.resolve()),
    }
