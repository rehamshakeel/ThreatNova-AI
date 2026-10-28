"""Application configuration module using pydantic-settings."""

from pathlib import Path
from typing import List, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Explicit path to the backend directory and .env file
BACKEND_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BACKEND_DIR / ".env"

SUPPORTED_LLM_PROVIDERS = ("none", "openai", "anthropic", "gemini")


class Settings(BaseSettings):
    APP_NAME: str = "ThreatNova AI Backend"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = True

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # CORS configuration for frontend
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:3002",
    ]

    # Database connection
    DATABASE_URL: str = f"sqlite:///{BACKEND_DIR.as_posix()}/threatnova.db"

    # VirusTotal v3 API Key (optional - uses demo fixtures if unset)
    VIRUSTOTAL_API_KEY: Optional[str] = None

    # LLM Provider Configuration (none | openai | anthropic | gemini)
    LLM_PROVIDER: str = "none"
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: Optional[str] = None

    # Dedicated Google Gemini Configuration
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # Outbound intelligence HTTP timeout
    REQUEST_TIMEOUT_SECONDS: float = 8.0

    @field_validator(
        "VIRUSTOTAL_API_KEY",
        "LLM_API_KEY",
        "LLM_MODEL",
        "GEMINI_API_KEY",
        "GEMINI_MODEL",
        mode="before",
    )
    @classmethod
    def empty_str_to_none(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = str(v).strip()
        return cleaned if cleaned else None

    @field_validator("LLM_PROVIDER", mode="before")
    @classmethod
    def validate_llm_provider(cls, v: Optional[str]) -> str:
        if not v or not str(v).strip():
            return "none"
        cleaned = str(v).strip().lower()
        if cleaned in SUPPORTED_LLM_PROVIDERS:
            return cleaned
        return "none"

    def get_gemini_api_key(self) -> Optional[str]:
        """Resolve active Gemini API key from GEMINI_API_KEY, LLM_API_KEY, or environment."""
        import os
        return (
            self.GEMINI_API_KEY
            or os.environ.get("GEMINI_API_KEY")
            or (self.LLM_API_KEY if self.LLM_PROVIDER in ("gemini", "none") else None)
        )

    def get_gemini_model(self) -> str:
        """Resolve active Gemini model identifier."""
        import os
        return (
            self.GEMINI_MODEL
            or os.environ.get("GEMINI_MODEL")
            or self.LLM_MODEL
            or "gemini-2.5-flash"
        )

    model_config = SettingsConfigDict(
        env_file=(str(ENV_FILE), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

