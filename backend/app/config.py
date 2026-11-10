from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "AICTE Application Validation & Compliance Verification Platform"
    PROJECT_ID: str = "SIH26261"
    VERSION: str = "0.1.0"

    # Database: Defaults to local SQLite for zero-config development; override with PostgreSQL URL in .env
    DATABASE_URL: str = "sqlite:///./aicte_platform.db"

    # JWT / RBAC Security
    SECRET_KEY: str = "super-secret-aicte-sih26261-dev-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Google Gemini API Key (used in Phase 3)
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # File storage directory for uploaded institutional documents
    UPLOAD_DIR: Path = Path("uploads")

    model_config = SettingsConfigDict(
        env_file=[
            Path(__file__).resolve().parent.parent / ".env",
            ".env",
            "backend/.env",
        ],
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
