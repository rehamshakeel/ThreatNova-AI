"""AI Threat Analyst API Router.

Endpoints for automated structured threat analysis and interactive context-aware
chat with the Gemini AI Threat Analyst.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models.investigation import InvestigationDB
from app.schemas.ai import (
    AIThreatAnalysisRequest,
    AIThreatAnalysisResponse,
    AIChatRequest,
    AIChatResponse,
)
from app.services.gemini_service import (
    analyze_investigation_with_gemini,
    chat_with_gemini,
)

router = APIRouter(prefix="/api/ai", tags=["AI Threat Analyst"])


def _extract_investigation_context(
    inv_db: Optional[InvestigationDB],
    inv_data: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Normalize investigation parameters from either DB record or client payload."""
    if inv_db:
        findings_raw = []
        for f in inv_db.findings:
            findings_raw.append({
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "source": f.source,
                "confidence": f.confidence or 75,
                "evidence": f.evidence or [],
            })
        return {
            "id": inv_db.id,
            "query": inv_db.query,
            "type": inv_db.type,
            "risk_score": inv_db.risk_score,
            "risk_level": inv_db.risk_level,
            "risk_confidence": inv_db.risk_confidence,
            "factors": inv_db.risk_factors or [],
            "findings": findings_raw,
            "domain_intel": inv_db.domain_intel or {},
            "db_instance": inv_db,
        }

    if inv_data:
        risk = inv_data.get("risk") or {}
        return {
            "id": inv_data.get("id", "inv-live"),
            "query": inv_data.get("query", "Unknown"),
            "type": inv_data.get("type", "domain"),
            "risk_score": risk.get("score", inv_data.get("risk_score", 50)),
            "risk_level": risk.get("level", inv_data.get("risk_level", "medium")),
            "risk_confidence": risk.get("confidence", inv_data.get("risk_confidence", 75)),
            "factors": risk.get("factors", inv_data.get("factors", [])),
            "findings": inv_data.get("findings", []),
            "domain_intel": inv_data.get("domainIntel") or inv_data.get("domain_intel") or {},
            "db_instance": None,
        }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Investigation not found in database and no investigation data payload provided.",
    )


@router.post("/analyze", response_model=AIThreatAnalysisResponse)
async def analyze_investigation(
    req: AIThreatAnalysisRequest,
    db: Session = Depends(get_db),
):
    """Analyze a completed investigation and generate a structured CTI threat report."""
    inv_db = None
    if req.investigation_id:
        inv_db = db.query(InvestigationDB).filter(InvestigationDB.id == req.investigation_id).first()

    ctx = _extract_investigation_context(inv_db, req.investigation_data)

    # Check if previously saved structured analysis exists in SQLite
    if inv_db and inv_db.ai_analysis:
        cached = inv_db.ai_analysis.get(req.language)
        if cached:
            try:
                return AIThreatAnalysisResponse(**cached)
            except Exception:
                pass

    analysis = await analyze_investigation_with_gemini(
        investigation_id=ctx["id"],
        indicator=ctx["query"],
        indicator_type=ctx["type"],
        risk_score=ctx["risk_score"],
        risk_level=ctx["risk_level"],
        risk_confidence=ctx["risk_confidence"],
        factors=ctx["factors"],
        findings=ctx["findings"],
        domain_intel=ctx["domain_intel"],
        language=req.language,
    )

    # Persist structured analysis to database if DB instance exists
    if inv_db:
        existing_ai_analysis = inv_db.ai_analysis or {}
        existing_ai_analysis[req.language] = analysis.model_dump()
        inv_db.ai_analysis = existing_ai_analysis
        # Also sync top-level ai_summary if empty
        if not inv_db.ai_summary:
            inv_db.ai_summary = analysis.executive_summary
        db.commit()

    return analysis


@router.post("/chat", response_model=AIChatResponse)
async def chat_investigation(
    req: AIChatRequest,
    db: Session = Depends(get_db),
):
    """Interactive conversational analyst assistant grounded in the current investigation."""
    inv_db = None
    if req.investigation_id:
        inv_db = db.query(InvestigationDB).filter(InvestigationDB.id == req.investigation_id).first()

    ctx = _extract_investigation_context(inv_db, req.investigation_data)

    chat_reply = await chat_with_gemini(
        investigation_id=ctx["id"],
        indicator=ctx["query"],
        indicator_type=ctx["type"],
        risk_score=ctx["risk_score"],
        risk_level=ctx["risk_level"],
        risk_confidence=ctx["risk_confidence"],
        factors=ctx["factors"],
        findings=ctx["findings"],
        domain_intel=ctx["domain_intel"],
        message=req.message,
        language=req.language,
        history=req.history,
    )

    return chat_reply


@router.get("/status")
def get_ai_status():
    """Retrieve Gemini AI Threat Analyst operational and configuration status."""
    gemini_key = settings.get_gemini_api_key()
    model = settings.get_gemini_model()
    is_configured = bool(gemini_key and gemini_key.strip())

    return {
        "status": "ready",
        "gemini_configured": is_configured,
        "model": model,
        "mode": "live_gemini" if is_configured else "heuristic_fallback",
        "provider": "google-gemini",
        "sdk": "google-genai",
        "description": (
            f"Active model: {model}. Ready for live CTI synthesis and context-aware chat."
            if is_configured
            else "Autonomous cybersecurity heuristic synthesis active. Configure GEMINI_API_KEY in backend/.env for live neural synthesis."
        ),
    }
