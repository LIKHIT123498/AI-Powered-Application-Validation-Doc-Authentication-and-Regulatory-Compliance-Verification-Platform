from enum import Enum


class UserRole(str, Enum):
    """PRD §3 User Personas"""
    APPLICANT = "applicant"       # Institution Applicant (Submitter)
    REVIEWER = "reviewer"         # AICTE Official (Reviewer / Approver)
    ADMIN = "admin"               # System Administrator (System Configurator)


class ApplicationCategory(str, Enum):
    """PRD §4.1 Category Identification based on Approval Process Handbook"""
    EOA = "EXTENSION_OF_APPROVAL"             # Extension of Approval (EoA)
    NEW_INSTITUTION = "NEW_INSTITUTION"       # Setting up a New Technical Institution
    INTAKE_INCREASE = "INCREASE_IN_INTAKE"    # Increase in Approved Intake / New Course
    INFRA_CHANGE = "CHANGE_OF_SITE_OR_INFRA"  # Change of Location / Infrastructure


class ApplicationStatus(str, Enum):
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    VALIDATING = "VALIDATING"
    DEFICIENCY_FLAGGED = "DEFICIENCY_FLAGGED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    RECTIFICATION_REQUESTED = "RECTIFICATION_REQUESTED"
    APPROVED_BY_REVIEWER = "APPROVED_BY_REVIEWER"
    REJECTED_BY_REVIEWER = "REJECTED_BY_REVIEWER"


class DocumentType(str, Enum):
    AFFIDAVIT = "AFFIDAVIT"
    FIRE_SAFETY_CERTIFICATE = "FIRE_SAFETY_CERTIFICATE"
    BUILDING_PLAN_CERTIFICATE = "BUILDING_PLAN_CERTIFICATE"
    LAND_OWNERSHIP_DOCUMENT = "LAND_OWNERSHIP_DOCUMENT"
    PREVIOUS_EOA_LETTER = "PREVIOUS_EOA_LETTER"
    ACCREDITATION_CERTIFICATE = "ACCREDITATION_CERTIFICATE"
    FACULTY_ROSTER = "FACULTY_ROSTER"
    INFRASTRUCTURE_EVIDENCE = "INFRASTRUCTURE_EVIDENCE"  # Photos / Floor plans


class VerificationStatus(str, Enum):
    """PRD §4.3 Status Logging for Verification Through Original Issuing Authorities"""
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    EXPIRED = "EXPIRED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class FlagCategory(str, Enum):
    """PRD §4.1 - §4.4 Validation & Anomaly Categories"""
    MISSING_DOCUMENT = "MISSING_DOCUMENT"
    INCOMPLETE_FIELD = "INCOMPLETE_FIELD"
    EXPIRED_DOCUMENT = "EXPIRED_DOCUMENT"
    CROSS_DOC_INCONSISTENCY = "CROSS_DOC_INCONSISTENCY"
    POTENTIAL_FORGERY_OR_ALTERATION = "POTENTIAL_FORGERY_OR_ALTERATION"
    DUPLICATE_SUBMISSION = "DUPLICATE_SUBMISSION"
    AUTHORITY_VERIFICATION_FAILURE = "AUTHORITY_VERIFICATION_FAILURE"
    INFRASTRUCTURE_DISCREPANCY = "INFRASTRUCTURE_DISCREPANCY"


class FlagSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
