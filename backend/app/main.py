"""ThreatNova AI - FastAPI Backend Application Entrypoint.

Provides autonomous threat investigation orchestration, multi-source intelligence correlation,
VirusTotal v3 reputation querying, explainable risk scoring, and D3 graph topology generation.
Scoreboard statistics, findings, and alerts endpoints enabled.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import SessionLocal, init_db
from app.models.investigation import FindingDB, InvestigationDB
from app.routers import (
    ai_router,
    alerts_router,
    findings_router,
    health_router,
    indicators_router,
    investigations_router,
)

# Initialize database tables on load
init_db()


def _seed_initial_demo_data():
    """Seed initial demonstration investigations into SQLite if database is newly initialized."""
    db = SessionLocal()
    try:
        count = db.query(InvestigationDB).count()
        if count == 0:
            now = datetime.now(timezone.utc)

            # Sample 1: dark-stealer-c2.net
            inv1 = InvestigationDB(
                id="inv-001",
                query="dark-stealer-c2.net",
                type="domain",
                status="complete",
                started_at=now,
                completed_at=now,
                risk_score=78,
                risk_level="high",
                risk_confidence=85,
                risk_explanation="High risk. Matched 7/90 threat intelligence engines for active RedLine/Stealer C2 infrastructure.",
                ai_summary="[AUTONOMOUS ANALYSIS] Domain 'dark-stealer-c2.net' functions as an active C2 communication relay. Outbound beaconing from internal hosts indicates high probability of credential exfiltration.",
                is_demo=True,
            )
            inv1.risk_factors = [
                {"name": "Threat Intelligence Consensus", "impact": 35, "description": "7/90 VirusTotal engines flagged domain"},
                {"name": "Self-Signed TLS Certificate", "impact": 18, "description": "Certificate issued by untrusted authority"},
                {"name": "Tor Gateway Proxy", "impact": 25, "description": "Resolved IP 198.51.100.23 is an active Tor exit node"},
            ]
            inv1.domain_intel = {
                "dns": [
                    {"type": "A", "name": "dark-stealer-c2.net", "value": "198.51.100.23", "ttl": 120},
                    {"type": "CNAME", "name": "login.dark-stealer-c2.net", "value": "dark-stealer-c2.net", "ttl": 120},
                ],
                "whois": {
                    "registrar": "NameCheap, Inc. (Privacy Protected)",
                    "createdDate": "2024-11-14T00:00:00Z",
                    "expiryDate": "2025-11-14T00:00:00Z",
                    "updatedDate": "2025-01-15T00:00:00Z",
                    "registrant": "Withheld for Privacy",
                    "nameServers": ["ns1.threat-dns.net", "ns2.threat-dns.net"],
                    "status": ["clientTransferProhibited"],
                },
                "ssl": {
                    "issuer": "CN=ThreatNet Internal CA, O=Untrusted",
                    "subject": "CN=dark-stealer-c2.net",
                    "validFrom": "2024-01-01T00:00:00Z",
                    "validTo": "2026-01-01T00:00:00Z",
                    "serialNumber": "7F:2E:4A:9C:11:3D",
                    "fingerprint": "SHA256:d8e9f0a1b2c3...",
                    "protocol": "TLS 1.3",
                    "keyExchange": "X25519",
                    "cipher": "CHACHA20_POLY1305_SHA256",
                    "isValid": False,
                },
                "ipInfo": {
                    "ip": "198.51.100.23",
                    "asn": "AS64496",
                    "org": "ThreatNet Autonomous System",
                    "country": "NL",
                    "city": "Amsterdam",
                    "isp": "ThreatNet Server Colocation",
                    "isProxy": True,
                    "isTor": True,
                    "isVPN": True,
                },
                "reputation": {
                    "score": 78,
                    "malicious": True,
                    "sources": [
                        {"name": "VirusTotal (Demo Fixture)", "result": "malicious", "detail": "7/90 engines flagged C2 node"},
                        {"name": "AlienVault OTX (Demo Fixture)", "result": "malicious", "detail": "Found in 4 threat pulses"},
                    ],
                    "categories": ["C2 Server", "Phishing Infrastructure"],
                    "firstSeen": "2024-11-14T00:00:00Z",
                    "lastSeen": "2025-01-15T00:00:00Z",
                },
            }
            inv1.graph_nodes = [
                {"id": "node-dark-stealer-c2.net", "label": "dark-stealer-c2.net", "type": "indicator", "risk": "high"},
                {"id": "ip-198.51.100.23", "label": "198.51.100.23", "type": "ip", "risk": "high"},
                {"id": "asn-AS64496", "label": "AS64496 (ThreatNet)", "type": "infrastructure", "risk": "medium"},
                {"id": "threat-c2", "label": "Stealer C2 Network", "type": "campaign", "risk": "critical"},
            ]
            inv1.graph_links = [
                {"source": "node-dark-stealer-c2.net", "target": "ip-198.51.100.23", "relationship": "RESOLVES_TO", "confidence": 0.98},
                {"source": "ip-198.51.100.23", "target": "asn-AS64496", "relationship": "ANNOUNCED_BY", "confidence": 0.92},
                {"source": "node-dark-stealer-c2.net", "target": "threat-c2", "relationship": "ATTRIBUTED_TO", "confidence": 0.88},
            ]
            inv1.ai_recommendations = [
                "Block outbound egress to dark-stealer-c2.net across enterprise firewalls and DNS sinkholes.",
                "Quarantine endpoints exhibiting beaconing connections to IP 198.51.100.23.",
                "Revoke active session tokens for user credentials identified in compromised browser keystores.",
            ]

            f1 = FindingDB(
                id="f-001",
                investigation_id="inv-001",
                title="Active Stealer C2 Infrastructure Identified",
                severity="critical",
                category="Threat Intelligence",
                description="Cross-correlated threat intelligence fixtures match active RedLine credential stealer operations.",
                source="ThreatNova Intelligence Engine",
                confidence=90,
                evidence=[{"type": "network", "label": "C2 Handshake", "content": "Beaconing observed to 198.51.100.23:4444"}],
                related_indicators=["198.51.100.23"],
                timestamp=now,
            )
            inv1.findings = [f1]

            # Sample 2: 198.51.100.23
            inv2 = InvestigationDB(
                id="inv-002",
                query="198.51.100.23",
                type="ip",
                status="complete",
                started_at=now,
                completed_at=now,
                risk_score=68,
                risk_level="high",
                risk_confidence=80,
                risk_explanation="Elevated risk due to verified Tor relay traits and open administration ports.",
                ai_summary="[AUTONOMOUS ANALYSIS] IP 198.51.100.23 operates as an anonymized egress proxy. Recommend restricting perimeter connectivity.",
                is_demo=True,
            )
            inv2.risk_factors = [
                {"name": "Tor Relay Infrastructure", "impact": 35, "description": "Verified active Tor network node"},
                {"name": "High-Risk ASN", "impact": 33, "description": "Autonomous System AS64496 flagged in security watchlists"},
            ]
            inv2.domain_intel = {
                "dns": [],
                "whois": {"registrar": "RIPE NCC", "createdDate": "2021-03-14T00:00:00Z", "expiryDate": "2026-03-14T00:00:00Z", "updatedDate": "2024-11-01T00:00:00Z", "registrant": "ThreatNet Colocation", "nameServers": [], "status": ["active"]},
                "ipInfo": {"ip": "198.51.100.23", "asn": "AS64496", "org": "ThreatNet Autonomous System", "country": "NL", "city": "Amsterdam", "isp": "ThreatNet Server Colocation", "isProxy": True, "isTor": True, "isVPN": True},
                "reputation": {"score": 68, "malicious": True, "sources": [], "categories": ["Tor Exit Relay"], "firstSeen": "2023-09-10T00:00:00Z", "lastSeen": "2025-01-15T00:00:00Z"},
            }
            inv2.graph_nodes = [
                {"id": "node-198.51.100.23", "label": "198.51.100.23", "type": "indicator", "risk": "high"},
                {"id": "asn-AS64496", "label": "AS64496", "type": "infrastructure", "risk": "medium"},
            ]
            inv2.graph_links = [
                {"source": "node-198.51.100.23", "target": "asn-AS64496", "relationship": "ANNOUNCED_BY", "confidence": 0.95},
            ]
            inv2.ai_recommendations = [
                "Implement geo-blocking and Tor exit blocking policies on external load balancers.",
                "Review remote authentication logs for logins originating from 198.51.100.23.",
            ]

            db.add(inv1)
            db.add(inv2)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to initialize SQLite database on startup."""
    init_db()
    _seed_initial_demo_data()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Autonomous Threat Investigation & Early-Warning Intelligence Backend for ThreatNova AI.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Configure Cross-Origin Resource Sharing (CORS) for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(health_router)
app.include_router(investigations_router)
app.include_router(findings_router)
app.include_router(alerts_router)
app.include_router(indicators_router)
app.include_router(ai_router)


@app.get("/", tags=["Root"])
def root():
    """Welcome endpoint providing service metadata and documentation links."""
    return {
        "service": settings.APP_NAME,
        "version": "1.0.1-reload-test",
        "status": "operational",
        "documentation": "/docs",
        "health": "/health",
        "apiEndpoints": {
            "investigations": "/api/investigations",
            "indicators": "/api/indicators/{type}/{value}",
            "ai": "/api/ai",
        },
    }
