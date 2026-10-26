from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.database import get_session
from app.models.models import User
from app.schemas.schemas import TokenResponse, UserCreate, UserRead
from app.services.audit_service import log_audit_event
from app.services.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication & RBAC (PRD §3)"])


@router.get("/demo-personas")
def list_demo_personas():
    """
    Returns pre-seeded demo credentials for the 3 PRD §3 User Personas so you can
    immediately test Role-Based Access Control (RBAC) in Swagger UI ('Authorize' button).
    """
    return {
        "password_for_all_demo_users": "password123",
        "personas": [
            {
                "persona": "Institution Applicant (Submitter)",
                "username": "applicant@apexedu.ac.in",
                "role": "applicant",
            },
            {
                "persona": "AICTE Official (Reviewer / Approver)",
                "username": "official@aicte-india.org",
                "role": "reviewer",
            },
            {
                "persona": "System Administrator (System Configurator)",
                "username": "admin@aicte-india.org",
                "role": "admin",
            },
        ],
    }


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(
    payload: UserCreate,
    session: Session = Depends(get_session),
):
    existing = session.exec(select(User).where(User.email == payload.email)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered.",
        )

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        institution_id=payload.institution_id,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    log_audit_event(
        session,
        action_type="USER_REGISTERED",
        entity_type="User",
        entity_id=str(user.id),
        actor=user,
        summary=f"User '{user.email}' registered with role '{user.role.value}'.",
    )
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """OAuth2 compatible token login (`username` is the user's email address)."""
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.email, "role": user.role.value, "user_id": user.id}
    )
    return TokenResponse(access_token=access_token, user=UserRead.model_validate(user, from_attributes=True))


@router.get("/me", response_model=UserRead)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
