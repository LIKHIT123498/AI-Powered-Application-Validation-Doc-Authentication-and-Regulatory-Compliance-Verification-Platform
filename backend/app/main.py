from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import applications, audit, auth, documents, rules
from app.config import settings
from app.database import init_db_and_seed
from app.services.sample_pdf_generator import generate_demo_pdfs


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db_and_seed()
    generate_demo_pdfs(Path("sample_docs"))
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "AI-enabled decision-support platform for AICTE (SIH26261) to automate preliminary "
        "validation of institutional applications, authenticate supporting documents, and "
        "verify regulatory compliance against the Approval Process Handbook."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(rules.router)
app.include_router(applications.router)
app.include_router(documents.router)
app.include_router(audit.router)


@app.get("/", tags=["Health"])
async def root():
    return {
        "project": settings.PROJECT_NAME,
        "project_id": settings.PROJECT_ID,
        "status": "Backend running successfully!",
        "docs_url": "/docs",
    }
