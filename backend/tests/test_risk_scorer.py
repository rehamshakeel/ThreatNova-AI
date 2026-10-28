"""Tests for risk assessment calculation engine."""

import pytest
from app.schemas.investigation import (
    DomainIntelligenceSchema,
    IPInfoSchema,
    IndicatorType,
    ReputationSourceSchema,
    Severity,
)
from app.services.risk_scorer import calculate_risk_assessment
from app.services.virustotal import VTLookupResult


def test_clean_indicator_scoring():
    vt_result = VTLookupResult(
        configured=False,
        status="unconfigured",
        message="Demo",
        is_demo=True,
        positives=0,
        total=80,
        malicious=False,
        categories=["Clean"],
        sources=[ReputationSourceSchema(name="VT", result="clean")],
    )
    domain_intel = DomainIntelligenceSchema(dns=[], whois=None, ssl=None, ipInfo=None)
    assessment = calculate_risk_assessment("clean-example.com", IndicatorType.DOMAIN, vt_result, domain_intel, [])

    assert assessment.score < 25
    assert assessment.level in (Severity.LOW, Severity.INFO)
    assert len(assessment.limitations) > 0


def test_malicious_tor_indicator_scoring():
    vt_result = VTLookupResult(
        configured=True,
        status="live_success",
        message="Live",
        is_demo=False,
        positives=12,
        total=85,
        malicious=True,
        categories=["C2 Server"],
    )
    ip_info = IPInfoSchema(
        ip="198.51.100.23",
        asn="AS64496",
        org="ThreatNet",
        country="NL",
        city="Amsterdam",
        isp="Colocation",
        isTor=True,
        isProxy=True,
    )
    domain_intel = DomainIntelligenceSchema(dns=[], whois=None, ssl=None, ipInfo=ip_info)
    assessment = calculate_risk_assessment("198.51.100.23", IndicatorType.IP, vt_result, domain_intel, [])

    assert assessment.score >= 60
    assert assessment.level in (Severity.HIGH, Severity.CRITICAL)
    assert any(f.name == "High Threat Feed Consensus" for f in assessment.factors)
    assert any(f.name == "Tor Anonymization Relay" for f in assessment.factors)
