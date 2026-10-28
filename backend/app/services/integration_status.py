"""Integration Status and Authentication Verification Service.

Safely checks the status and live authentication for VirusTotal v3 and LLM providers
(OpenAI, Anthropic, Gemini) without ever logging, printing, or exposing API secrets.
"""

import logging
from typing import Dict, Optional
import httpx
from app.config import settings
from app.schemas.investigation import IntegrationHealth

logger = logging.getLogger(__name__)

# Official Minimal Verification Endpoints
VT_VERIFY_URL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
OPENAI_MODELS_URL = "https://api.openai.com/v1/models"
ANTHROPIC_MODELS_URL = "https://api.anthropic.com/v1/models"
GEMINI_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"


async def check_virustotal_auth(
    api_key: Optional[str] = None,
    verify_live: bool = False,
    timeout: float = 5.0,
) -> IntegrationHealth:
    """Evaluate VirusTotal v3 configuration and optionally verify authentication."""
    key = api_key if api_key is not None else settings.VIRUSTOTAL_API_KEY

    # 1. Key Missing
    if not key or not key.strip():
        return IntegrationHealth(
            status="KEY MISSING",
            configured=False,
            authenticated=False,
            mode="demo_fixture",
            detail="VIRUSTOTAL_API_KEY is not configured. ThreatNova AI is utilizing verified demonstration fixtures.",
            provider="virustotal",
        )

    clean_key = key.strip()

    # 2. Key Configured, Not Verified (offline mode / fast health check)
    if not verify_live:
        return IntegrationHealth(
            status="KEY CONFIGURED, NOT VERIFIED",
            configured=True,
            authenticated=False,
            mode="live",
            detail="VIRUSTOTAL_API_KEY is present in environment, but live upstream authentication has not yet been checked.",
            provider="virustotal",
        )

    # 3. Live Minimal Authentication Verification
    headers = {
        "x-apikey": clean_key,
        "Accept": "application/json",
        "User-Agent": "ThreatNova-AI-Verification/1.0",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(VT_VERIFY_URL, headers=headers)

            if resp.status_code == 200:
                return IntegrationHealth(
                    status="AUTHENTICATION SUCCESSFUL",
                    configured=True,
                    authenticated=True,
                    mode="live",
                    detail="Successfully authenticated with VirusTotal v3 API.",
                    provider="virustotal",
                )
            elif resp.status_code in (401, 403):
                return IntegrationHealth(
                    status="INVALID KEY / UNAUTHORIZED",
                    configured=True,
                    authenticated=False,
                    mode="demo_fixture",
                    detail=f"VirusTotal rejected the provided API key (HTTP {resp.status_code}).",
                    provider="virustotal",
                )
            elif resp.status_code == 429:
                return IntegrationHealth(
                    status="QUOTA OR RATE LIMIT EXCEEDED",
                    configured=True,
                    authenticated=False,
                    mode="demo_fixture",
                    detail="VirusTotal API rate limit or monthly quota exceeded (HTTP 429).",
                    provider="virustotal",
                )
            else:
                return IntegrationHealth(
                    status="NETWORK OR PROVIDER ERROR",
                    configured=True,
                    authenticated=False,
                    mode="demo_fixture",
                    detail=f"VirusTotal returned unexpected response (HTTP {resp.status_code}).",
                    provider="virustotal",
                )
    except httpx.TimeoutException:
        return IntegrationHealth(
            status="NETWORK OR PROVIDER ERROR",
            configured=True,
            authenticated=False,
            mode="demo_fixture",
            detail=f"Connection to VirusTotal API timed out after {timeout} seconds.",
            provider="virustotal",
        )
    except Exception as exc:
        return IntegrationHealth(
            status="NETWORK OR PROVIDER ERROR",
            configured=True,
            authenticated=False,
            mode="demo_fixture",
            detail=f"Network error communicating with VirusTotal: {type(exc).__name__}",
            provider="virustotal",
        )


async def check_llm_auth(
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    verify_live: bool = False,
    timeout: float = 5.0,
) -> IntegrationHealth:
    """Evaluate LLM provider configuration and optionally verify authentication."""
    gemini_key = settings.get_gemini_api_key()
    prov = (provider or settings.LLM_PROVIDER or "none").strip().lower()
    if prov in ("none", "") and gemini_key:
        prov = "gemini"
    key = api_key if api_key is not None else (gemini_key if prov == "gemini" else settings.LLM_API_KEY)

    # 1. No provider or key missing
    if prov in ("none", "") or not key or not key.strip():
        return IntegrationHealth(
            status="KEY MISSING",
            configured=False,
            authenticated=False,
            mode="heuristic_fallback",
            detail=(
                "No external LLM credentials configured. ThreatNova AI autonomous rule-based "
                "heuristic reasoning engine is active."
            ),
            provider=prov,
        )

    clean_key = key.strip()

    # 2. Key configured, not verified
    if not verify_live:
        return IntegrationHealth(
            status="KEY CONFIGURED, NOT VERIFIED",
            configured=True,
            authenticated=False,
            mode="live",
            detail=f"API key configured for '{prov}', but live upstream authentication has not yet been verified.",
            provider=prov,
        )

    # 3. Live Minimal Authentication Verification
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if prov == "openai":
                headers = {
                    "Authorization": f"Bearer {clean_key}",
                    "User-Agent": "ThreatNova-AI-Verification/1.0",
                }
                resp = await client.get(OPENAI_MODELS_URL, headers=headers)

            elif prov == "anthropic":
                headers = {
                    "x-api-key": clean_key,
                    "anthropic-version": "2023-06-01",
                    "User-Agent": "ThreatNova-AI-Verification/1.0",
                }
                resp = await client.get(ANTHROPIC_MODELS_URL, headers=headers)

            elif prov == "gemini":
                headers = {
                    "x-goog-api-key": clean_key,
                    "User-Agent": "ThreatNova-AI-Verification/1.0",
                }
                resp = await client.get(GEMINI_MODELS_URL, headers=headers)

            else:
                return IntegrationHealth(
                    status="NETWORK OR PROVIDER ERROR",
                    configured=True,
                    authenticated=False,
                    mode="heuristic_fallback",
                    detail=f"Unsupported LLM provider '{prov}'. Supported: openai, anthropic, gemini, none.",
                    provider=prov,
                )

            if resp.status_code == 200:
                return IntegrationHealth(
                    status="AUTHENTICATION SUCCESSFUL",
                    configured=True,
                    authenticated=True,
                    mode="live",
                    detail=f"Successfully authenticated with {prov.capitalize()} API.",
                    provider=prov,
                )
            elif resp.status_code in (400, 401, 403):
                return IntegrationHealth(
                    status="INVALID KEY / UNAUTHORIZED",
                    configured=True,
                    authenticated=False,
                    mode="heuristic_fallback",
                    detail=f"{prov.capitalize()} API rejected the provided credentials (HTTP {resp.status_code}).",
                    provider=prov,
                )
            elif resp.status_code == 429:
                return IntegrationHealth(
                    status="QUOTA OR RATE LIMIT EXCEEDED",
                    configured=True,
                    authenticated=False,
                    mode="heuristic_fallback",
                    detail=f"{prov.capitalize()} API quota or rate limit exceeded (HTTP 429).",
                    provider=prov,
                )
            else:
                return IntegrationHealth(
                    status="NETWORK OR PROVIDER ERROR",
                    configured=True,
                    authenticated=False,
                    mode="heuristic_fallback",
                    detail=f"{prov.capitalize()} API returned unexpected response (HTTP {resp.status_code}).",
                    provider=prov,
                )

    except httpx.TimeoutException:
        return IntegrationHealth(
            status="NETWORK OR PROVIDER ERROR",
            configured=True,
            authenticated=False,
            mode="heuristic_fallback",
            detail=f"Connection to {prov.capitalize()} API timed out after {timeout} seconds.",
            provider=prov,
        )
    except Exception as exc:
        return IntegrationHealth(
            status="NETWORK OR PROVIDER ERROR",
            configured=True,
            authenticated=False,
            mode="heuristic_fallback",
            detail=f"Network error communicating with {prov.capitalize()}: {type(exc).__name__}",
            provider=prov,
        )


async def get_integrations_health(verify_live: bool = False) -> Dict[str, IntegrationHealth]:
    """Retrieve health and verification status across all external integrations."""
    vt_health = await check_virustotal_auth(verify_live=verify_live)
    llm_health = await check_llm_auth(verify_live=verify_live)

    return {
        "virustotal": vt_health,
        "llm": llm_health,
    }
