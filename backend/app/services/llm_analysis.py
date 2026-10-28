"""LLM Analysis Service.

Generates executive threat summaries, forensic explanations, and prioritized defensive
mitigations using either environment-configured LLM providers (OpenAI, Anthropic, Gemini)
or an autonomous expert heuristic reasoning pipeline when API keys are absent.
Strictly distinguishes AI-generated synthesis from verified empirical source data.
"""

import json
import logging
from typing import List, Tuple
import httpx
from app.config import settings
from app.schemas.investigation import (
    DomainIntelligenceSchema,
    FindingSchema,
    IndicatorType,
    RiskAssessmentSchema,
)

logger = logging.getLogger(__name__)


async def generate_ai_analysis(
    indicator: str,
    indicator_type: IndicatorType,
    risk: RiskAssessmentSchema,
    findings: List[FindingSchema],
    domain_intel: DomainIntelligenceSchema,
) -> Tuple[str, List[str], bool, str]:
    """Generate executive intelligence brief and actionable defensive playbooks.

    Returns:
        Tuple[str, List[str], bool, str]:
        (summary_text, recommendations_list, is_ai_generated, source_attribution)
    """
    gemini_key = settings.get_gemini_api_key()
    provider = (settings.LLM_PROVIDER or "none").lower().strip()
    if gemini_key and provider == "none":
        provider = "gemini"
    api_key = gemini_key if provider == "gemini" else settings.LLM_API_KEY

    # 1. Check if external LLM API is configured
    if api_key and provider in ("openai", "anthropic", "gemini"):
        try:
            return await _call_external_llm(
                provider, api_key, indicator, indicator_type, risk, findings, domain_intel
            )
        except Exception as exc:
            logger.warning(
                f"External LLM call failed ({exc}); falling back to autonomous rule-based synthesis.",
                exc_info=True,
            )

    # 2. Autonomous heuristic reasoning fallback
    return _generate_heuristic_analysis(indicator, indicator_type, risk, findings, domain_intel)


async def _call_external_llm(
    provider: str,
    api_key: str,
    indicator: str,
    indicator_type: IndicatorType,
    risk: RiskAssessmentSchema,
    findings: List[FindingSchema],
    domain_intel: DomainIntelligenceSchema,
) -> Tuple[str, List[str], bool, str]:
    """Execute live outbound prompt to configured LLM provider."""
    system_prompt = (
        "You are ThreatNova AI's Lead Cybersecurity Analyst. "
        "Analyze the provided threat intelligence findings and generate a JSON response with: "
        "'summary' (2-3 sentences concise threat brief) and 'recommendations' (array of 3-5 specific SOC defensive actions). "
        "Never invent facts not present in the input. Return ONLY raw valid JSON."
    )

    user_prompt = f"""
TARGET INDICATOR: {indicator} (Type: {indicator_type.value})
RISK ASSESSMENT: {risk.score}/100 ({risk.level.value.upper()}), Confidence: {risk.confidence}%
FINDINGS COUNT: {len(findings)}
FACTORS: {', '.join(f.name for f in risk.factors)}
IP INFO: {domain_intel.ipInfo.model_dump_json() if domain_intel.ipInfo else 'N/A'}
VIRUSTOTAL DETECTION: {domain_intel.reputation.score if domain_intel.reputation else '0'}%
"""

    timeout = settings.REQUEST_TIMEOUT_SECONDS

    if provider == "openai":
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": settings.LLM_MODEL or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            summary = parsed.get("summary", "")
            recs = parsed.get("recommendations", [])
            return (
                f"[AI SYNTHESIS via OpenAI {settings.LLM_MODEL or 'gpt-4o-mini'}] {summary}",
                recs or ["Enforce baseline monitoring."],
                True,
                f"OpenAI ({settings.LLM_MODEL or 'gpt-4o-mini'})",
            )

    elif provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": settings.LLM_MODEL or "claude-3-5-sonnet-20241022",
            "max_tokens": 600,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["content"][0]["text"]
            parsed = json.loads(content)
            summary = parsed.get("summary", "")
            recs = parsed.get("recommendations", [])
            return (
                f"[AI SYNTHESIS via Anthropic Claude] {summary}",
                recs,
                True,
                "Anthropic Claude",
            )

    elif provider == "gemini":
        model = settings.get_gemini_model()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        headers = {
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}],
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2,
            },
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(content)
            summary = parsed.get("summary", "")
            recs = parsed.get("recommendations", [])
            return (
                f"[AI SYNTHESIS via Google {model}] {summary}",
                recs or ["Enforce baseline monitoring."],
                True,
                f"Google Gemini ({model})",
            )

    # Fallback if unknown provider specified
    return _generate_heuristic_analysis(indicator, indicator_type, risk, findings, domain_intel)


def _generate_heuristic_analysis(
    indicator: str,
    indicator_type: IndicatorType,
    risk: RiskAssessmentSchema,
    findings: List[FindingSchema],
    domain_intel: DomainIntelligenceSchema,
) -> Tuple[str, List[str], bool, str]:
    """Autonomous deterministic synthesis when external LLM API key is not configured."""
    level = risk.level.value.upper()
    score = risk.score
    factor_names = [f.name for f in risk.factors]

    # Build executive summary
    if score >= 80:
        summary = (
            f"CRITICAL THREAT BRIEF: Indicator '{indicator}' presents active threat severity (Risk Score: {score}/100). "
            f"Correlated factors ({', '.join(factor_names[:2]) or 'Multi-vector flags'}) indicate direct alignment with known "
            f"adversary infrastructure or malicious delivery mechanisms. Immediate defensive containment is strongly advised."
        )
    elif score >= 60:
        summary = (
            f"HIGH RISK ADVISORY: Target '{indicator}' exhibits multiple anomalous intelligence characteristics (Score: {score}/100). "
            f"Signals identify network anonymization, unverified certificates, or preliminary reputation flags. "
            f"SOC teams should inspect recent perimeter logs for anomalous beaconing."
        )
    elif score >= 40:
        summary = (
            f"ELEVATED MONITORING: Indicator '{indicator}' scored {score}/100 in baseline heuristics. "
            f"Identified factors indicate operational exposure or mixed telemetry without definitive compromise evidence. "
            f"Recommend correlation with internal EDR and proxy logs."
        )
    else:
        summary = (
            f"LOW THREAT FOOTPRINT: Indicator '{indicator}' scored {score}/100 with no definitive indicators of compromise detected. "
            f"Baseline DNS and reputation telemetry remain consistent with standard benign operations. "
            f"Standard periodic monitoring remains sufficient."
        )

    # Build prioritized recommendations
    recommendations: List[str] = []

    if indicator_type in (IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL):
        if score >= 60:
            recommendations.append(
                f"Block outbound egress to {indicator} across perimeter next-generation firewalls (NGFW) and DNS sinkholes."
            )
            recommendations.append(
                f"Query SIEM/EDR repositories for any past TCP/UDP connections involving '{indicator}' within the last 30 days."
            )
            if domain_intel.ipInfo and domain_intel.ipInfo.isTor:
                recommendations.append(
                    "Block incoming traffic from associated Tor exit relays and mandate multi-factor challenge on remote access gateways."
                )
        else:
            recommendations.append(f"Add '{indicator}' to low-priority SIEM threat watchlists.")
            recommendations.append("Continue periodic automated reputation re-scanning.")

    elif indicator_type == IndicatorType.HASH:
        if score >= 60:
            recommendations.append(f"Isolate host endpoints currently executing binary sample hash {indicator}.")
            recommendations.append("Trigger automated memory dump and snapshot forensic analysis on affected nodes.")
            recommendations.append(f"Blacklist hash {indicator} in global Endpoint Detection and Response (EDR) policy.")
        else:
            recommendations.append("Submit file to isolated sandbox for dynamic behavioral detonation.")

    elif indicator_type == IndicatorType.EMAIL:
        recommendations.append(f"Quarantine any inbound email messages originating from '{indicator}'.")
        recommendations.append("Review mail gateway DMARC/SPF/DKIM alignment logs for recent spoofing attempts.")

    elif indicator_type == IndicatorType.USERNAME:
        recommendations.append(f"Cross-reference username '{indicator}' against corporate Active Directory and IAM audit logs.")
        recommendations.append("Audit privilege escalation attempts associated with this identity.")

    # Always ensure at least 2 recommendations
    if len(recommendations) < 2:
        recommendations.append("Document case details in ticketing system for compliance audit trail.")

    return (
        f"[AUTONOMOUS REASONING ENGINE - NO EXTERNAL LLM API KEY CONFIGURED] {summary}",
        recommendations,
        False,
        "ThreatNova Heuristic Synthesis Engine v1.0",
    )
