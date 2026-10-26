from typing import Generator
from sqlmodel import Session, SQLModel, create_engine, select

from app.config import settings
from app.models.enums import ApplicationCategory, DocumentType, UserRole
from app.models.models import AuditLog, ChecklistRule, Institution, User

connect_args = (
    {"check_same_thread": False}
    if settings.DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args=connect_args,
)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


def init_db_and_seed() -> None:
    """Create database tables and seed default AICTE personas, institution & handbook rules."""
    from app.services.security import hash_password

    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        # 1. Seed a sample Technical Institution with historical AICTE records (PRD §2.2 & §4.1)
        inst = session.exec(
            select(Institution).where(Institution.aicte_permanent_id == "1-4928173650")
        ).first()
        if not inst:
            inst = Institution(
                aicte_permanent_id="1-4928173650",
                name="Apex Institute of Engineering and Technology",
                state="Maharashtra",
                district="Pune",
                address="Plot No. 42, Knowledge Park, Hinjewadi Phase II, Pune - 411057",
                established_year=2014,
                historical_records={
                    "previous_eoa_year": "2025-26",
                    "previous_eoa_reference": "F.No. Western/1-4928173650/2025/EOA",
                    "approved_intake_total": 420,
                    "courses": [
                        {"name": "B.Tech Computer Science & Engineering", "intake": 180},
                        {"name": "B.Tech Artificial Intelligence & Data Science", "intake": 120},
                        {"name": "B.Tech Electronics & Telecommunication", "intake": 120},
                    ],
                    "land_area_acres": 7.5,
                    "built_up_area_sqm": 14800,
                    "faculty_count_registered": 32,
                    "nba_accredited": True,
                },
            )
            session.add(inst)
            session.commit()
            session.refresh(inst)

        # 2. Seed the 3 PRD §3 User Personas if not present
        demo_users = [
            {
                "email": "applicant@apexedu.ac.in",
                "full_name": "Dr. Rajesh Kulkarni (Principal - Apex Institute)",
                "role": UserRole.APPLICANT,
                "institution_id": inst.id,
            },
            {
                "email": "official@aicte-india.org",
                "full_name": "Smt. Ananya Sharma (AICTE Scrutiny Officer)",
                "role": UserRole.REVIEWER,
                "institution_id": None,
            },
            {
                "email": "admin@aicte-india.org",
                "full_name": "System Administrator (AICTE Regulation Bureau)",
                "role": UserRole.ADMIN,
                "institution_id": None,
            },
        ]
        for u_data in demo_users:
            existing = session.exec(
                select(User).where(User.email == u_data["email"])
            ).first()
            if not existing:
                session.add(
                    User(
                        email=u_data["email"],
                        full_name=u_data["full_name"],
                        hashed_password=hash_password("password123"),
                        role=u_data["role"],
                        institution_id=u_data["institution_id"],
                    )
                )
        session.commit()

        # 3. Seed configurable AICTE Approval Process Handbook Checklist Rules (PRD §4.1 & §4.4)
        existing_rules = session.exec(select(ChecklistRule)).first()
        if not existing_rules:
            default_rules = [
                ChecklistRule(
                    handbook_year="2026-27",
                    category=ApplicationCategory.EOA,
                    document_type=DocumentType.AFFIDAVIT,
                    rule_name="Standard Affidavit-2 on Non-Judicial Stamp Paper",
                    description="Sworn affidavit confirming adherence to AICTE norms, intake, land, and faculty requirements.",
                    is_mandatory=True,
                    check_expiry=False,
                    required_fields=[
                        "institution_name",
                        "aicte_permanent_id",
                        "deponent_name",
                        "issue_date",
                        "stamp_paper_number",
                    ],
                    consistency_targets={
                        "institution_name": "Institution.name",
                        "aicte_permanent_id": "Institution.aicte_permanent_id",
                    },
                ),
                ChecklistRule(
                    handbook_year="2026-27",
                    category=ApplicationCategory.EOA,
                    document_type=DocumentType.FIRE_SAFETY_CERTIFICATE,
                    rule_name="Valid Fire Safety Certificate from Competent Authority",
                    description="Must be issued by the State Fire & Emergency Services and valid for the current academic year.",
                    is_mandatory=True,
                    check_expiry=True,
                    required_fields=[
                        "institution_name",
                        "certificate_number",
                        "issuing_authority",
                        "issue_date",
                        "expiry_date",
                        "building_area_sqm",
                    ],
                    consistency_targets={
                        "institution_name": "Institution.name",
                        "building_area_sqm": "Institution.historical_records.built_up_area_sqm",
                    },
                ),
                ChecklistRule(
                    handbook_year="2026-27",
                    category=ApplicationCategory.EOA,
                    document_type=DocumentType.PREVIOUS_EOA_LETTER,
                    rule_name="Previous Academic Year Extension of Approval (EoA) Letter",
                    description="Cross-verifies baseline intake and courses with historical AICTE database records.",
                    is_mandatory=True,
                    check_expiry=False,
                    required_fields=[
                        "institution_name",
                        "aicte_permanent_id",
                        "eoa_reference_number",
                        "approved_intake_total",
                    ],
                    consistency_targets={
                        "eoa_reference_number": "Institution.historical_records.previous_eoa_reference",
                        "approved_intake_total": "Institution.historical_records.approved_intake_total",
                    },
                ),
                ChecklistRule(
                    handbook_year="2026-27",
                    category=ApplicationCategory.EOA,
                    document_type=DocumentType.INFRASTRUCTURE_EVIDENCE,
                    rule_name="Infrastructure & Laboratory Compliance Evidence",
                    description="Floor plans and geo-tagged facility photos checked against Approval Process Handbook norms.",
                    is_mandatory=True,
                    check_expiry=False,
                    required_fields=[
                        "built_up_area_sqm",
                        "classrooms_count",
                        "laboratories_count",
                    ],
                    infrastructure_thresholds={
                        "min_classroom_area_sqm": 66,
                        "min_laboratory_area_sqm": 66,
                        "min_built_up_area_sqm": 10000,
                        "barrier_free_environment_required": True,
                    },
                ),
            ]
            session.add_all(default_rules)
            session.commit()

            session.add(
                AuditLog(
                    actor_role="SYSTEM",
                    action_type="SYSTEM_SEEDED",
                    entity_type="ChecklistRule",
                    summary="Initialized AICTE Approval Process Handbook 2026-27 checklist rules and demo personas.",
                    details={"rules_seeded": len(default_rules)},
                )
            )
            session.commit()
