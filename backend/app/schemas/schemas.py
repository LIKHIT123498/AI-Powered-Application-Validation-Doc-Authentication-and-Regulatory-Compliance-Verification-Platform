from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field

from app.models.enums import (
    ApplicationCategory,
    ApplicationStatus,
    DocumentType,
    FlagCategory,
    FlagSeverity,
    UserRole,
    VerificationStatus,
)


# --- Auth & User Schemas ---
class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str = Field(min_length=6)
    role: UserRole = UserRole.APPLICANT
    institution_id: Optional[int] = None


class UserRead(BaseModel):
    id: int
    email: str
    full_name: str
    role: UserRole
    institution_id: Optional[int]
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead


# --- Institution Schemas ---
class InstitutionCreate(BaseModel):
    aicte_permanent_id: str
    name: str
    state: str
    district: str
    address: str
    established_year: int
    historical_records: Dict[str, Any] = Field(default_factory=dict)


class InstitutionRead(BaseModel):
    id: int
    aicte_permanent_id: str
    name: str
    state: str
    district: str
    address: str
    established_year: int
    historical_records: Dict[str, Any]
    created_at: datetime


# --- Configurable Checklist Rule Schemas ---
class ChecklistRuleCreate(BaseModel):
    handbook_year: str = "2026-27"
    category: ApplicationCategory
    document_type: DocumentType
    rule_name: str
    description: str
    is_mandatory: bool = True
    check_expiry: bool = True
    required_fields: List[str] = Field(default_factory=list)
    consistency_targets: Dict[str, str] = Field(default_factory=dict)
    infrastructure_thresholds: Dict[str, Any] = Field(default_factory=dict)


class ChecklistRuleUpdate(BaseModel):
    rule_name: Optional[str] = None
    description: Optional[str] = None
    is_mandatory: Optional[bool] = None
    check_expiry: Optional[bool] = None
    required_fields: Optional[List[str]] = None
    consistency_targets: Optional[Dict[str, str]] = None
    infrastructure_thresholds: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


# --- Application Schemas ---
class ApplicationCreate(BaseModel):
    institution_id: int
    academic_year: str = "2026-27"
    category: ApplicationCategory = ApplicationCategory.EOA
    declared_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Applicant-submitted metadata (e.g., requested_intake, built_up_area_sqm, courses).",
    )


class ChecklistItemStatus(BaseModel):
    rule_id: int
    document_type: DocumentType
    rule_name: str
    is_mandatory: bool
    required_fields: List[str]
    uploaded: bool
    document_id: Optional[int] = None
    verification_status: Optional[VerificationStatus] = None


class ApplicationDetailResponse(BaseModel):
    id: int
    application_number: str
    institution_id: int
    academic_year: str
    category: ApplicationCategory
    status: ApplicationStatus
    declared_data: Dict[str, Any]
    validation_summary: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    applicable_checklist: List[ChecklistItemStatus]
    historical_aicte_records: Dict[str, Any]
