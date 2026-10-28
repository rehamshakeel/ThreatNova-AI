"""Health check and integration status endpoints."""

from datetime import datetime, timezone
from typing import Dict
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.schemas.investigation import HealthResponse, IntegrationHealth
from app.services.integration_status import get_integrations_health

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
@router.get("/api/health", response_model=HealthResponse)
async def health_check(
    verify: bool = Query(
        False,
        description="Optionally perform live upstream authentication ping against configured API keys.",
    ),
    db: Session = Depends(get_db),
):
    """Comprehensive health check checking API, database, and integration readiness."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"

    integrations = await get_integrations_health(verify_live=verify)
    gemini_key = settings.get_gemini_api_key()
    llm_configured = bool((settings.LLM_API_KEY and settings.LLM_PROVIDER != "none") or gemini_key)
    provider = settings.LLM_PROVIDER if (settings.LLM_PROVIDER and settings.LLM_PROVIDER != "none") else ("gemini" if gemini_key else "none")

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        version=settings.APP_VERSION,
        database=db_status,
        virustotalConfigured=bool(settings.VIRUSTOTAL_API_KEY),
        llmConfigured=llm_configured,
        llmProvider=provider,
        timestamp=datetime.now(timezone.utc).isoformat(),
        integrations=integrations,
    )


@router.get("/health/integrations", response_model=Dict[str, IntegrationHealth])
@router.get("/api/health/integrations", response_model=Dict[str, IntegrationHealth])
async def health_integrations(
    verify: bool = Query(
        False,
        description="Optionally execute a minimal safe authentication ping against configured external providers.",
    ),
):
    """Detailed diagnostic endpoint reporting the exact status and authentication of each external integration."""
    return await get_integrations_health(verify_live=verify)

