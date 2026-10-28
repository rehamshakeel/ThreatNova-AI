"""Transparent and configurable risk scoring engine.

Evaluates multi-vector threat intelligence evidence and returns an explainable risk score,
severity classification, confidence percentage, scoring factors, and explicit limitations.
"""

from typing import List, Tuple
from app.schemas.investigation import (
    DomainIntelligenceSchema,
    FindingSchema,
    IndicatorType,
    RiskAssessmentSchema,
    RiskFactorSchema,
    Severity,
)
from app.services.virustotal import VTLookupResult


def calculate_risk_assessment(
    indicator: str,
    indicator_type: IndicatorType,
    vt_result: VTLookupResult,
    domain_intel: DomainIntelligenceSchema,
    findings: List[FindingSchema],
) -> RiskAssessmentSchema:
    """Calculate deterministic and explainable risk score across intelligence dimensions."""
    score = 0
    factors: List[RiskFactorSchema] = []
    limitations: List[str] = [
        "Absence of threat feed detections does not guarantee an indicator is harmless or safe.",
        "IP geolocation reflects upstream network transit, colocation, or VPN gateways rather than a physical individual.",
    ]

    # 1. Threat Intelligence & VirusTotal Signals (Up to 45 pts)
    if vt_result.total > 0:
        ratio = vt_result.positives / vt_result.total
        if vt_result.positives >= 10:
            impact = 45
            factors.append(
                RiskFactorSchema(
                    name="High Threat Feed Consensus",
                    impact=impact,
                    description=f"{vt_result.positives}/{vt_result.total} security engines flagged indicator as malicious.",
                )
            )
            score += impact
        elif vt_result.positives >= 3:
            impact = 35
            factors.append(
                RiskFactorSchema(
                    name="Threat Intelligence Matches",
                    impact=impact,
                    description=f"{vt_result.positives}/{vt_result.total} threat intelligence engines detected suspicious/malicious activity.",
                )
            )
            score += impact
        elif vt_result.positives >= 1:
            impact = 20
            factors.append(
                RiskFactorSchema(
                    name="Isolated Security Vendor Flag",
                    impact=impact,
                    description=f"Flagged by {vt_result.positives} engine. May represent early-stage detection or anomalous telemetry.",
                )
            )
            score += impact
        else:
            factors.append(
                RiskFactorSchema(
                    name="Clean Intelligence Consensus",
                    impact=0,
                    description=f"Zero malicious detections across {vt_result.total} active scanning engines.",
                )
            )
    elif vt_result.malicious:
        # Fallback fixture match
        impact = 38
        factors.append(
            RiskFactorSchema(
                name="Known Threat Intelligence Correlation",
                impact=impact,
                description="Matched demonstration threat intelligence fixtures for known adversary campaigns.",
            )
        )
        score += impact

    if vt_result.is_demo:
        limitations.append(
            "Evaluation incorporates demonstration fixture intelligence because live external VirusTotal API keys are unconfigured."
        )

    # 2. Network Traits: Tor, VPN, Proxy, Autonomous System (Up to 25 pts)
    ip_info = domain_intel.ipInfo
    if ip_info:
        if ip_info.isTor:
            impact = 22
            factors.append(
                RiskFactorSchema(
                    name="Tor Anonymization Relay",
                    impact=impact,
                    description=f"IP {ip_info.ip} is verified as an active Tor network node, frequently leveraged for C2 obfuscation.",
                )
            )
            score += impact
        elif ip_info.isVPN or ip_info.isProxy:
            impact = 14
            factors.append(
                RiskFactorSchema(
                    name="Anonymized Egress / Commercial VPN",
                    impact=impact,
                    description="Host utilizes commercial VPN or proxy routing, masking originating client infrastructure.",
                )
            )
            score += impact

        if "threat" in ip_info.org.lower() or "bulletproof" in ip_info.isp.lower():
            impact = 15
            factors.append(
                RiskFactorSchema(
                    name="High-Risk Autonomous System",
                    impact=impact,
                    description=f"Assigned ASN ({ip_info.asn}) historically associated with bulletproof hosting facilities.",
                )
            )
            score += impact

    # 3. SSL / TLS Telemetry (Up to 15 pts)
    if domain_intel.ssl:
        if not domain_intel.ssl.isValid or "self-signed" in domain_intel.ssl.issuer.lower() or "untrusted" in domain_intel.ssl.issuer.lower():
            impact = 18
            factors.append(
                RiskFactorSchema(
                    name="Untrusted / Self-Signed TLS Certificate",
                    impact=impact,
                    description=f"SSL certificate issued by '{domain_intel.ssl.issuer}'. Lacks validation from trusted CA root store.",
                )
            )
            score += impact

    # 4. Domain & WHOIS Anomalies (Up to 15 pts)
    if domain_intel.whois:
        status_str = " ".join(domain_intel.whois.status).lower()
        if "serverhold" in status_str or "prohibited" in status_str:
            impact = 10
            factors.append(
                RiskFactorSchema(
                    name="Registrar Security Flags",
                    impact=impact,
                    description="WHOIS registry records indicate active dispute, legal hold, or security lockout statuses.",
                )
            )
            score += impact

    # 5. Additional Heuristics for URLs / Hashes
    if indicator_type == IndicatorType.URL:
        if "@" in indicator or any(ext in indicator.lower() for ext in [".exe", ".scr", ".vbs", ".bat", ".ps1"]):
            impact = 16
            factors.append(
                RiskFactorSchema(
                    name="Suspicious URL Payload Indicator",
                    impact=impact,
                    description="URL contains inline executable payloads or obfuscated authentication tokens.",
                )
            )
            score += impact

    # Final score normalization (clamped to 0-100)
    final_score = max(0, min(100, score))

    # Determine Severity Level
    if final_score >= 80:
        level = Severity.CRITICAL
    elif final_score >= 60:
        level = Severity.HIGH
    elif final_score >= 40:
        level = Severity.MEDIUM
    elif final_score >= 15:
        level = Severity.LOW
    else:
        level = Severity.INFO

    # Determine Confidence Level
    confidence = 50
    if vt_result.total > 0 and not vt_result.is_demo:
        confidence += 30
    elif vt_result.is_demo:
        confidence += 15
    if domain_intel.dns:
        confidence += 10
    if domain_intel.ssl:
        confidence += 5
    if domain_intel.ipInfo:
        confidence += 10
    confidence = min(95, max(30, confidence))

    explanation = (
        f"Calculated risk score of {final_score}/100 ({level.value.upper()}) based on {len(factors)} correlated factor(s) "
        f"with {confidence}% analytical confidence. "
        + ("Demonstration intelligence was utilized where live APIs were unconfigured." if vt_result.is_demo else "Verified against live external telemetry feeds.")
    )

    return RiskAssessmentSchema(
        score=final_score,
        level=level,
        confidence=confidence,
        factors=factors,
        explanation=explanation,
        limitations=limitations,
    )
