from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import Column, JSON
from sqlmodel import Field, Relationship, SQLModel

from app.models.enums import (
    ApplicationCategory,
    ApplicationStatus,
    DocumentType,
    FlagCategory,
    FlagSeverity,
    UserRole,
    VerificationStatus,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    """PRD §3 User Personas with Role-Based Access Control (RBAC)."""
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    full_name: str
    hashed_password: str
    role: UserRole = Field(default=UserRole.APPLICANT, index=True)
    institution_id: Optional[int] = Field(default=None, foreign_key="institutions.id")
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utc_now)


class Institution(SQLModel, table=True):
    """
    Technical Institution profile + historical AICTE records (PRD §2.2 & §4.1).
    `historical_records` stores authorized AICTE baseline data (previous EoA intake,
    approved land area, address, accreditation status, etc.) to reduce redundant checks
    and enable cross-verification.
    """
    __tablename__ = "institutions"

    id: Optional[int] = Field(default=None, primary_key=True)
    aicte_permanent_id: str = Field(index=True, unique=True)  # e.g., "1-1234567890"
    name: str = Field(index=True)
    state: str
    district: str
    address: str
    established_year: int
    historical_records: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)

    applications: List["Application"] = Relationship(back_populates="institution")


class ChecklistRule(SQLModel, table=True):
    """
    Configurable regulatory checklist rules derived from the AICTE Approval Process Handbook
    (PRD §4.1, §4.4, §5 Configurability).
    """
    __tablename__ = "checklist_rules"

    id: Optional[int] = Field(default=None, primary_key=True)
    handbook_year: str = Field(default="2026-27", index=True)
    category: ApplicationCategory = Field(index=True)
    document_type: DocumentType = Field(index=True)
    rule_name: str
    description: str
    is_mandatory: bool = Field(default=True)
    check_expiry: bool = Field(default=True)
    required_fields: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    consistency_targets: Dict[str, str] = Field(
        default_factory=dict,
        sa_column=Column(JSON),
    )  # e.g., {"institution_name": "Institution.name", "land_area_acres": "historical_records.land_area_acres"}
    infrastructure_thresholds: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON),
    )  # e.g., {"min_classroom_area_sqm": 66, "min_labs": 4}
    is_active: bool = Field(default=True)
    updated_at: datetime = Field(default_factory=utc_now)


class Application(SQLModel, table=True):
    """Institutional Application submitted to AICTE (e.g., EoA, Increase in Intake)."""
    __tablename__ = "applications"

    id: Optional[int] = Field(default=None, primary_key=True)
    application_number: str = Field(index=True, unique=True)  # e.g., "AICTE-2026-EOA-0001"
    institution_id: int = Field(foreign_key="institutions.id", index=True)
    submitted_by_user_id: int = Field(foreign_key="users.id")
    academic_year: str = Field(default="2026-27")
    category: ApplicationCategory = Field(index=True)
    status: ApplicationStatus = Field(default=ApplicationStatus.DRAFT, index=True)
    declared_data: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON),
    )  # Data declared in application form (requested intake, courses, built-up area, etc.)
    validation_summary: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON),
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    institution: Optional[Institution] = Relationship(back_populates="applications")
    documents: List["Document"] = Relationship(back_populates="application")
    flags: List["ValidationFlag"] = Relationship(back_populates="application")


class Document(SQLModel, table=True):
    """
    Supporting document uploaded for an Application (PRD §4.1 - §4.3).
    Stores OCR text, PDF structural metadata, Gemini extracted fields, SHA-256 hash
    for duplicate detection, and external authority verification status.
    """
    __tablename__ = "documents"

    id: Optional[int] = Field(default=None, primary_key=True)
    application_id: int = Field(foreign_key="applications.id", index=True)
    document_type: DocumentType = Field(index=True)
    filename: str
    file_path: str
    mime_type: str = Field(default="application/pdf")
    file_size_bytes: int = Field(default=0)
    sha256_hash: str = Field(index=True)  # Detects duplicate uploads across applications

    # OCR & Extraction outputs (Phase 2 & 3)
    raw_ocr_text: Optional[str] = Field(default=None)
    pdf_metadata: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    extracted_fields: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    # Issuing Authority Verification (PRD §4.3)
    issuing_authority: Optional[str] = Field(default=None)
    document_urn_or_id: Optional[str] = Field(default=None, index=True)
    issue_date: Optional[str] = Field(default=None)
    expiry_date: Optional[str] = Field(default=None)
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.PENDING,
        index=True,
    )
    verification_details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    uploaded_at: datetime = Field(default_factory=utc_now)

    application: Optional[Application] = Relationship(back_populates="documents")
    flags: List["ValidationFlag"] = Relationship(back_populates="document")


class ValidationFlag(SQLModel, table=True):
    """
    Explainable AI & Rule-based flags requiring human-in-the-loop review (PRD §4.2, §4.4, §5).
    Every flag explicitly records the reason, links to evidence, and remains advisory
    until reviewed by an AICTE Official.
    """
    __tablename__ = "validation_flags"

    id: Optional[int] = Field(default=None, primary_key=True)
    application_id: int = Field(foreign_key="applications.id", index=True)
    document_id: Optional[int] = Field(default=None, foreign_key="documents.id", index=True)
    rule_id: Optional[int] = Field(default=None, foreign_key="checklist_rules.id")

    flag_category: FlagCategory = Field(index=True)
    severity: FlagSeverity = Field(default=FlagSeverity.MEDIUM, index=True)
    field_name: Optional[str] = Field(default=None)
    reason: str  # Explainable AI statement (e.g., "Mismatched font / modification date after issue date")
    evidence_snippet: Optional[str] = Field(default=None)  # Exact text / metadata / comparison values
    page_number: Optional[int] = Field(default=None)
    is_advisory: bool = Field(default=True)  # Strictly decision-support per PRD §2.3 & §5

    # Human-in-the-loop resolution by AICTE Official
    is_resolved: bool = Field(default=False, index=True)
    reviewer_action: Optional[str] = Field(default=None)  # e.g., "CONFIRMED_DEFICIENCY", "DISMISSED_FALSE_POSITIVE"
    reviewer_notes: Optional[str] = Field(default=None)
    reviewed_by_user_id: Optional[int] = Field(default=None, foreign_key="users.id")
    reviewed_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now)

    application: Optional[Application] = Relationship(back_populates="flags")
    document: Optional[Document] = Relationship(back_populates="flags")


class AuditLog(SQLModel, table=True):
    """
    Strict, immutable log of rules applied, records checked, API responses,
    alerts generated, observations, and actions taken (PRD §4.5).
    """
    __tablename__ = "audit_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    application_id: Optional[int] = Field(default=None, foreign_key="applications.id", index=True)
    actor_user_id: Optional[int] = Field(default=None, foreign_key="users.id", index=True)
    actor_role: str = Field(default="SYSTEM")  # SYSTEM, AI_ENGINE, APPLICANT, REVIEWER, ADMIN
    action_type: str = Field(index=True)       # e.g., "APPLICATION_CREATED", "RULE_APPLIED", "ANOMALY_FLAGGED"
    entity_type: str                           # e.g., "Application", "Document", "ChecklistRule"
    entity_id: Optional[str] = Field(default=None)
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    timestamp: datetime = Field(default_factory=utc_now, index=True)
