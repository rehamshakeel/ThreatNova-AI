"""Pydantic schemas mirroring ThreatNova AI frontend TypeScript definitions."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    USERNAME = "username"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceSchema(BaseModel):
    type: str  # log, screenshot, network, file, dns, whois, certificate
    label: str
    content: str


class FindingSchema(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: List[EvidenceSchema] = Field(default_factory=list)
    timestamp: str
    source: str
    confidence: Optional[int] = 75
    relatedIndicators: Optional[List[str]] = Field(default_factory=list)


class RiskFactorSchema(BaseModel):
    name: str
    impact: int
    description: str


class RiskAssessmentSchema(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Severity
    confidence: int = Field(ge=0, le=100)
    factors: List[RiskFactorSchema] = Field(default_factory=list)
    explanation: str
    limitations: Optional[List[str]] = Field(default_factory=list)


class DNSRecordSchema(BaseModel):
    type: str
    name: str
    value: str
    ttl: int = 300


class WhoisDataSchema(BaseModel):
    registrar: str
    createdDate: str
    expiryDate: str
    updatedDate: str
    registrant: str
    nameServers: List[str] = Field(default_factory=list)
    status: List[str] = Field(default_factory=list)


class SSLCertificateSchema(BaseModel):
    issuer: str
    subject: str
    validFrom: str
    validTo: str
    serialNumber: str
    fingerprint: str
    protocol: str
    keyExchange: str
    cipher: str
    isValid: bool


class GeolocationSchema(BaseModel):
    latitude: float
    longitude: float
    city: str
    region: str
    country: str
    countryCode: str
    org: str
    asn: str
    ip: str
    resolved_ip: str
    source: str
    retrieved_at: str
    isProxy: Optional[bool] = False
    isTor: Optional[bool] = False
    isVPN: Optional[bool] = False
    is_cdn_edge: Optional[bool] = False
    note: Optional[str] = None


class IPInfoSchema(BaseModel):
    ip: str
    asn: str
    org: str
    country: str
    city: str
    isp: str
    isProxy: bool = False
    isTor: bool = False
    isVPN: bool = False
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    region: Optional[str] = None
    countryCode: Optional[str] = None
    source: Optional[str] = None
    retrieved_at: Optional[str] = None


class ReputationSourceSchema(BaseModel):
    name: str
    result: str  # clean, suspicious, malicious, unknown
    detail: Optional[str] = None


class ReputationDataSchema(BaseModel):
    score: int
    malicious: bool
    sources: List[ReputationSourceSchema] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    firstSeen: str
    lastSeen: str


class DomainIntelligenceSchema(BaseModel):
    dns: List[DNSRecordSchema] = Field(default_factory=list)
    whois: Optional[WhoisDataSchema] = None
    ssl: Optional[SSLCertificateSchema] = None
    ipInfo: Optional[IPInfoSchema] = None
    reputation: Optional[ReputationDataSchema] = None
    geo: Optional[GeolocationSchema] = None


class ThreatGraphNodeSchema(BaseModel):
    id: str
    label: str
    type: str  # indicator, ip, domain, url, hash, report, actor, malware, campaign, vulnerability, infrastructure
    risk: Severity
    details: Optional[Dict[str, str]] = None


class ThreatGraphLinkSchema(BaseModel):
    source: str
    target: str
    relationship: str
    confidence: float = 0.85


class ThreatGraphDataSchema(BaseModel):
    nodes: List[ThreatGraphNodeSchema] = Field(default_factory=list)
    links: List[ThreatGraphLinkSchema] = Field(default_factory=list)


class InvestigationCreate(BaseModel):
    query: str = Field(..., min_length=1, max_length=512)
    type: Optional[IndicatorType] = None


class InvestigationResponse(BaseModel):
    id: str
    query: str
    type: IndicatorType
    status: str
    startedAt: str
    completedAt: Optional[str] = None
    risk: RiskAssessmentSchema
    findings: List[FindingSchema] = Field(default_factory=list)
    domainIntel: Optional[DomainIntelligenceSchema] = None
    graphData: Optional[ThreatGraphDataSchema] = None
    aiSummary: Optional[str] = None
    aiRecommendations: Optional[List[str]] = Field(default_factory=list)
    aiAnalysis: Optional[Dict[str, Any]] = None
    isDemo: bool = False
    geolocation: Optional[GeolocationSchema] = None

    model_config = ConfigDict(from_attributes=True)


class InvestigationListItem(BaseModel):
    id: str
    query: str
    type: IndicatorType
    status: str
    startedAt: str
    completedAt: Optional[str] = None
    risk: RiskAssessmentSchema
    findingCount: int = 0
    isDemo: bool = False
    geolocation: Optional[GeolocationSchema] = None


class AnalysisResponse(BaseModel):
    investigationId: str
    indicator: str
    indicatorType: IndicatorType
    summary: str
    explanation: str
    recommendations: List[str]
    source: str
    isAiGenerated: bool


class IntegrationHealth(BaseModel):
    status: str  # "KEY MISSING" | "KEY CONFIGURED, NOT VERIFIED" | "AUTHENTICATION SUCCESSFUL" | "INVALID KEY / UNAUTHORIZED" | "QUOTA OR RATE LIMIT EXCEEDED" | "NETWORK OR PROVIDER ERROR"
    configured: bool
    authenticated: bool
    mode: str  # "live" | "demo_fixture" | "heuristic_fallback"
    detail: str
    provider: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    virustotalConfigured: bool
    llmConfigured: bool
    llmProvider: str
    timestamp: str
    integrations: Optional[Dict[str, IntegrationHealth]] = None


class DashboardStatsResponse(BaseModel):
    totalInvestigations: int = 0
    completedInvestigations: int = 0
    activeScans: int = 0
    highRiskAlerts: int = 0
    correlatedEntities: int = 0
    findingsBySeverity: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


class AlertSchema(BaseModel):
    id: str
    title: str
    severity: Severity
    indicator: Optional[str] = None
    message: str
    source: str
    timestamp: str
    read: bool = False
    investigationId: Optional[str] = None


