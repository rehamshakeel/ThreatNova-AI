"""Investigation management and analysis API endpoints."""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.investigation import FindingDB, InvestigationDB
from app.schemas.investigation import (
    AnalysisResponse,
    DashboardStatsResponse,
    DomainIntelligenceSchema,
    EvidenceSchema,
    FindingSchema,
    IndicatorType,
    InvestigationCreate,
    InvestigationListItem,
    InvestigationResponse,
    RiskAssessmentSchema,
    RiskFactorSchema,
    Severity,
    ThreatGraphDataSchema,
    ThreatGraphLinkSchema,
    ThreatGraphNodeSchema,
)
from app.config import settings
from app.services.correlator import build_threat_graph
from app.services.enrichment import enrich_indicator
from app.services.gemini_service import analyze_investigation_with_gemini
from app.services.llm_analysis import generate_ai_analysis
from app.services.risk_scorer import calculate_risk_assessment
from app.services.validator import normalize_indicator
from app.services.virustotal import lookup_virustotal

router = APIRouter(prefix="/api/investigations", tags=["Investigations"])


def _serialize_investigation(inv: InvestigationDB) -> InvestigationResponse:
    """Serialize SQLAlchemy InvestigationDB model into frontend-compatible Pydantic response."""
    # Findings conversion
    findings_list: List[FindingSchema] = []
    for f in inv.findings:
        evidence_items = [
            EvidenceSchema(
                type=e.get("type", "log"),
                label=e.get("label", "Evidence Item"),
                content=str(e.get("content", "")),
            )
            for e in f.evidence
        ]
        findings_list.append(
            FindingSchema(
                id=f.id,
                title=f.title,
                severity=Severity(f.severity) if f.severity in Severity._value2member_map_ else Severity.MEDIUM,
                category=f.category,
                description=f.description,
                evidence=evidence_items,
                timestamp=f.timestamp.isoformat() if f.timestamp else datetime.now(timezone.utc).isoformat(),
                source=f.source,
                confidence=f.confidence or 75,
                relatedIndicators=f.related_indicators or [],
            )
        )

    # Risk assessment conversion
    raw_factors = inv.risk_factors or []
    risk_factors = [
        RiskFactorSchema(
            name=rf.get("name", "Risk Signal"),
            impact=rf.get("impact", 0),
            description=rf.get("description", ""),
        )
        for rf in raw_factors
    ]

    risk_schema = RiskAssessmentSchema(
        score=inv.risk_score,
        level=Severity(inv.risk_level) if inv.risk_level in Severity._value2member_map_ else Severity.LOW,
        confidence=inv.risk_confidence,
        factors=risk_factors,
        explanation=inv.risk_explanation,
        limitations=[
            "Missing evidence is not proof of safety.",
            "IP geolocation reflects upstream network transit, colocation, or VPN gateways rather than a physical individual.",
        ],
    )

    # Domain intelligence
    domain_intel_data = inv.domain_intel
    domain_intel_schema = DomainIntelligenceSchema(**domain_intel_data) if domain_intel_data else None

    # Geolocation resolution: from domain_intel_schema.geo or raw domain_intel_data
    geo_schema: Optional[GeolocationSchema] = None
    if domain_intel_schema and domain_intel_schema.geo:
        geo_schema = domain_intel_schema.geo
    elif isinstance(domain_intel_data, dict) and domain_intel_data.get("geo"):
        try:
            geo_schema = GeolocationSchema(**domain_intel_data["geo"])
        except Exception:
            geo_schema = None

    # Graph data
    nodes_data = inv.graph_nodes or []
    links_data = inv.graph_links or []
    graph_schema = ThreatGraphDataSchema(
        nodes=[ThreatGraphNodeSchema(**n) for n in nodes_data],
        links=[ThreatGraphLinkSchema(**l) for l in links_data],
    )

    return InvestigationResponse(
        id=inv.id,
        query=inv.query,
        type=IndicatorType(inv.type),
        status=inv.status,
        startedAt=inv.started_at.isoformat() if inv.started_at else datetime.now(timezone.utc).isoformat(),
        completedAt=inv.completed_at.isoformat() if inv.completed_at else None,
        risk=risk_schema,
        findings=findings_list,
        domainIntel=domain_intel_schema,
        graphData=graph_schema,
        aiSummary=inv.ai_summary,
        aiRecommendations=inv.ai_recommendations or [],
        aiAnalysis=inv.ai_analysis or {},
        isDemo=inv.is_demo,
        geolocation=geo_schema,
    )


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreate,
    db: Session = Depends(get_db),
):
    """Initiate an autonomous cyber investigation across multi-source intelligence stages.

    Validates indicator, executes threat intelligence lookup, computes explainable risk,
    generates entity correlation graph, and packages forensic findings.
    """
    # 1. Validation and Normalization
    try:
        normalized_query, resolved_type = normalize_indicator(payload.query, payload.type)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )

    investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc)

    # 2. VirusTotal Reputation Intelligence
    vt_result = await lookup_virustotal(normalized_query, resolved_type)

    # 3. Domain, WHOIS, DNS, and IP Geolocation Enrichment
    domain_intel = await enrich_indicator(normalized_query, resolved_type, vt_result)

    # 4. Synthesize Forensic Findings
    findings_to_create: List[FindingDB] = []
    finding_schemas: List[FindingSchema] = []

    # Finding A: Threat Feed finding if flagged
    if vt_result.malicious or vt_result.positives > 0:
        f1_id = f"f-{uuid.uuid4().hex[:6]}"
        f1_desc = f"Indicator correlated with {vt_result.positives}/{vt_result.total} scanning engines in VirusTotal. Identified categories: {', '.join(vt_result.categories)}."
        f1_evidence = [
            {"type": "log", "label": "VirusTotal Detection Ratio", "content": f"{vt_result.positives}/{vt_result.total} engines flagged malicious"},
            {"type": "network", "label": "Threat Categories", "content": ", ".join(vt_result.categories)},
        ]
        finding_db = FindingDB(
            id=f1_id,
            investigation_id=investigation_id,
            title="Known Malicious Threat Intelligence Match",
            severity="critical" if vt_result.positives >= 10 else "high",
            category="Threat Intelligence",
            description=f1_desc,
            source="VirusTotal v3 API" if vt_result.configured else "Threat Intelligence Fixture",
            confidence=90 if vt_result.configured else 80,
            evidence=f1_evidence,
            related_indicators=[],
            timestamp=start_time,
        )
        findings_to_create.append(finding_db)
        finding_schemas.append(
            FindingSchema(
                id=f1_id,
                title=finding_db.title,
                severity=Severity(finding_db.severity),
                category=finding_db.category,
                description=f1_desc,
                evidence=[EvidenceSchema(**e) for e in f1_evidence],
                timestamp=start_time.isoformat(),
                source=finding_db.source,
                confidence=finding_db.confidence,
                relatedIndicators=[],
            )
        )

    # Finding B: Network Anonymization if Tor/VPN detected
    if domain_intel.ipInfo and (domain_intel.ipInfo.isTor or domain_intel.ipInfo.isVPN):
        f2_id = f"f-{uuid.uuid4().hex[:6]}"
        trait = "Tor Anonymization Exit Node" if domain_intel.ipInfo.isTor else "Commercial VPN Gateway"
        f2_evidence = [
            {"type": "network", "label": "Routing Anomaly", "content": f"Egress IP {domain_intel.ipInfo.ip} (ASN: {domain_intel.ipInfo.asn}) is an active {trait}"},
            {"type": "whois", "label": "Geolocation", "content": f"{domain_intel.ipInfo.city}, {domain_intel.ipInfo.country}"},
        ]
        finding_db2 = FindingDB(
            id=f2_id,
            investigation_id=investigation_id,
            title=f"Network Obfuscation: {trait}",
            severity="high" if domain_intel.ipInfo.isTor else "medium",
            category="Network Telemetry",
            description=f"Traffic egress is routed through {trait}. Origin identity is shielded from standard perimeter telemetry.",
            source="Network Recon Engine",
            confidence=85,
            evidence=f2_evidence,
            related_indicators=[domain_intel.ipInfo.ip],
            timestamp=start_time,
        )
        findings_to_create.append(finding_db2)
        finding_schemas.append(
            FindingSchema(
                id=f2_id,
                title=finding_db2.title,
                severity=Severity(finding_db2.severity),
                category=finding_db2.category,
                description=finding_db2.description,
                evidence=[EvidenceSchema(**e) for e in f2_evidence],
                timestamp=start_time.isoformat(),
                source=finding_db2.source,
                confidence=finding_db2.confidence,
                relatedIndicators=[domain_intel.ipInfo.ip],
            )
        )

    # Finding C: Baseline reconnaissance record if clean
    if not findings_to_create:
        f_clean_id = f"f-{uuid.uuid4().hex[:6]}"
        f_clean_evidence = [{"type": "dns", "label": "Validation", "content": "Syntax verified. No malicious indicators found."}]
        finding_clean = FindingDB(
            id=f_clean_id,
            investigation_id=investigation_id,
            title="Clean Baseline Telemetry",
            severity="info",
            category="Overall Reconnaissance",
            description=f"No threat intelligence flags or malicious network traits detected for '{normalized_query}'.",
            source="Autonomous Recon Pipeline",
            confidence=90,
            evidence=f_clean_evidence,
            related_indicators=[],
            timestamp=start_time,
        )
        findings_to_create.append(finding_clean)
        finding_schemas.append(
            FindingSchema(
                id=f_clean_id,
                title=finding_clean.title,
                severity=Severity.INFO,
                category=finding_clean.category,
                description=finding_clean.description,
                evidence=[EvidenceSchema(**e) for e in f_clean_evidence],
                timestamp=start_time.isoformat(),
                source=finding_clean.source,
                confidence=90,
                relatedIndicators=[],
            )
        )

    # 5. Transparent Risk Assessment Calculation
    risk_assessment = calculate_risk_assessment(
        indicator=normalized_query,
        indicator_type=resolved_type,
        vt_result=vt_result,
        domain_intel=domain_intel,
        findings=finding_schemas,
    )

    # 6. Build D3-compatible Entity Correlation Graph
    graph_data = build_threat_graph(
        indicator=normalized_query,
        indicator_type=resolved_type,
        risk=risk_assessment,
        domain_intel=domain_intel,
        vt_result=vt_result,
        findings=finding_schemas,
    )

    # 7. AI Threat Analyst Structured Synthesis
    ai_analysis_data = {}
    try:
        structured_ai = await analyze_investigation_with_gemini(
            investigation_id=investigation_id,
            indicator=normalized_query,
            indicator_type=resolved_type.value,
            risk_score=risk_assessment.score,
            risk_level=risk_assessment.level.value,
            risk_confidence=risk_assessment.confidence,
            factors=[rf.model_dump() for rf in risk_assessment.factors],
            findings=[f.model_dump() for f in finding_schemas],
            domain_intel=domain_intel.model_dump(),
            language="en",
        )
        ai_summary = structured_ai.executive_summary
        ai_recs = [f"{a.priority}: {a.title} - {a.reason}" for a in structured_ai.recommended_actions]
        ai_analysis_data = {"en": structured_ai.model_dump()}
    except Exception as exc:
        ai_summary, ai_recs, _, _ = await generate_ai_analysis(
            indicator=normalized_query,
            indicator_type=resolved_type,
            risk=risk_assessment,
            findings=finding_schemas,
            domain_intel=domain_intel,
        )

    completed_time = datetime.now(timezone.utc)

    # 8. Persist to SQLite Database
    db_investigation = InvestigationDB(
        id=investigation_id,
        query=normalized_query,
        type=resolved_type.value,
        status="complete",
        started_at=start_time,
        completed_at=completed_time,
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.level.value,
        risk_confidence=risk_assessment.confidence,
        risk_explanation=risk_assessment.explanation,
        ai_summary=ai_summary,
        is_demo=vt_result.is_demo,
    )
    db_investigation.risk_factors = [rf.model_dump() for rf in risk_assessment.factors]
    db_investigation.domain_intel = domain_intel.model_dump()
    db_investigation.graph_nodes = [n.model_dump() for n in graph_data.nodes]
    db_investigation.graph_links = [l.model_dump() for l in graph_data.links]
    db_investigation.ai_recommendations = ai_recs
    db_investigation.ai_analysis = ai_analysis_data
    db_investigation.findings = findings_to_create

    db.add(db_investigation)
    db.commit()
    db.refresh(db_investigation)

    return _serialize_investigation(db_investigation)


@router.get("", response_model=List[InvestigationListItem])
def list_investigations(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    type: Optional[IndicatorType] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Retrieve historical cyber investigations with optional type and keyword filtering."""
    query = db.query(InvestigationDB)

    if type:
        query = query.filter(InvestigationDB.type == type.value)

    if q and q.strip():
        search_pattern = f"%{q.strip().lower()}%"
        query = query.filter(InvestigationDB.query.ilike(search_pattern))

    records = query.order_by(InvestigationDB.started_at.desc()).offset(skip).limit(limit).all()

    items: List[InvestigationListItem] = []
    for inv in records:
        raw_factors = inv.risk_factors or []
        factors = [
            RiskFactorSchema(
                name=rf.get("name", "Risk Signal"),
                impact=rf.get("impact", 0),
                description=rf.get("description", ""),
            )
            for rf in raw_factors
        ]
        d_intel = inv.domain_intel
        geo_item: Optional[GeolocationSchema] = None
        if isinstance(d_intel, dict) and d_intel.get("geo"):
            try:
                geo_item = GeolocationSchema(**d_intel["geo"])
            except Exception:
                geo_item = None

        items.append(
            InvestigationListItem(
                id=inv.id,
                query=inv.query,
                type=IndicatorType(inv.type),
                status=inv.status,
                startedAt=inv.started_at.isoformat() if inv.started_at else datetime.now(timezone.utc).isoformat(),
                completedAt=inv.completed_at.isoformat() if inv.completed_at else None,
                risk=RiskAssessmentSchema(
                    score=inv.risk_score,
                    level=Severity(inv.risk_level) if inv.risk_level in Severity._value2member_map_ else Severity.LOW,
                    confidence=inv.risk_confidence,
                    factors=factors,
                    explanation=inv.risk_explanation,
                ),
                findingCount=len(inv.findings),
                isDemo=inv.is_demo,
                geolocation=geo_item,
            )
        )

    return items


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Aggregate scoreboard metrics across persisted investigation records and findings in SQLite."""
    total = db.query(InvestigationDB).count()
    completed = db.query(InvestigationDB).filter(InvestigationDB.status == "complete").count()
    active = db.query(InvestigationDB).filter(InvestigationDB.status == "scanning").count()

    finding_severities = db.query(FindingDB.severity, func.count(FindingDB.id)).group_by(FindingDB.severity).all()
    sev_dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in finding_severities:
        if sev in sev_dict:
            sev_dict[sev] = cnt

    critical_high_findings = sev_dict["critical"] + sev_dict["high"]
    critical_high_invs = db.query(InvestigationDB).filter(
        (InvestigationDB.risk_level.in_(["critical", "high"])) | (InvestigationDB.risk_score >= 60)
    ).count()
    high_risk_alerts = max(critical_high_findings, critical_high_invs)

    unique_entities = set()
    inv_rows = db.query(InvestigationDB.query, InvestigationDB._graph_nodes).all()
    for q, gn_json in inv_rows:
        if q and q.strip():
            unique_entities.add(q.strip().lower())
        if gn_json:
            try:
                nodes = json.loads(gn_json)
                for n in nodes:
                    lbl = n.get("label") or n.get("id")
                    if lbl:
                        unique_entities.add(str(lbl).strip().lower())
            except Exception:
                pass

    return DashboardStatsResponse(
        totalInvestigations=total,
        completedInvestigations=completed,
        activeScans=active,
        highRiskAlerts=high_risk_alerts,
        correlatedEntities=len(unique_entities),
        findingsBySeverity=sev_dict,
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve full investigation record including forensic evidence, intelligence, and correlation graph."""
    inv = db.query(InvestigationDB).filter(InvestigationDB.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )
    return _serialize_investigation(inv)


@router.delete("/{investigation_id}", status_code=status.HTTP_200_OK)
def delete_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Delete an investigation record and all associated findings from SQLite."""
    inv = db.query(InvestigationDB).filter(InvestigationDB.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )
    db.delete(inv)
    db.commit()
    return {"status": "success", "message": f"Investigation '{investigation_id}' was deleted."}


@router.get("/{investigation_id}/graph", response_model=ThreatGraphDataSchema)
def get_investigation_graph(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve the D3.js force-directed graph representation for an investigation."""
    inv = db.query(InvestigationDB).filter(InvestigationDB.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )

    nodes = [ThreatGraphNodeSchema(**n) for n in (inv.graph_nodes or [])]
    links = [ThreatGraphLinkSchema(**l) for l in (inv.graph_links or [])]
    return ThreatGraphDataSchema(nodes=nodes, links=links)


@router.get("/{investigation_id}/analysis", response_model=AnalysisResponse)
def get_investigation_analysis(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve AI-synthesized intelligence summary and prioritized defensive recommendations."""
    inv = db.query(InvestigationDB).filter(InvestigationDB.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )

    return AnalysisResponse(
        investigationId=inv.id,
        indicator=inv.query,
        indicatorType=IndicatorType(inv.type),
        summary=inv.ai_summary or "No executive summary available.",
        explanation=inv.risk_explanation,
        recommendations=inv.ai_recommendations or ["Enforce standard monitoring controls."],
        source="ThreatNova Autonomous Analysis Engine",
        isAiGenerated=bool(settings.LLM_API_KEY and settings.LLM_PROVIDER != "none"),
    )
