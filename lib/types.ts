// lib/types.ts

// Analyst roles for demo identity
export type AnalystRole = 'Security Analyst' | 'Threat Researcher' | 'Student Researcher';

// Analyst profile stored in localStorage
export interface AnalystProfile {
  name: string;
  role?: AnalystRole;
  avatarInitials: string;
  theme: 'dark';
}

export interface InterfacePreferences {
  compactTables: boolean;
  reduceMotion: boolean;
}

// Investigation input types
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'username';

export interface InvestigationInput {
  query: string;
  type: IndicatorType;
}

// Severity levels
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Finding / evidence
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: Evidence[];
  timestamp: string;
  source: string;
  confidence?: number;
  relatedIndicators?: string[];
}

export interface Evidence {
  type: 'log' | 'screenshot' | 'network' | 'file' | 'dns' | 'whois' | 'certificate';
  label: string;
  content: string;
}

// Risk score with explanation
export interface RiskAssessment {
  score: number;          // 0–100
  level: Severity;
  confidence: number;     // 0–100
  factors: RiskFactor[];
  explanation: string;
}

export interface RiskFactor {
  name: string;
  impact: number;        // contribution to overall score
  description: string;
}

// Geolocation telemetry
export interface GeolocationData {
  latitude: number;
  longitude: number;
  city: string;
  region: string;
  country: string;
  countryCode: string;
  org: string;
  asn: string;
  ip: string;
  resolved_ip: string;
  source: string;
  retrieved_at: string;
  isProxy?: boolean;
  isTor?: boolean;
  isVPN?: boolean;
  is_cdn_edge?: boolean;
  note?: string;
}

// Investigation record
export interface Investigation {
  id: string;
  query: string;
  type: IndicatorType;
  status: 'scanning' | 'complete' | 'error';
  startedAt: string;
  completedAt?: string;
  risk: RiskAssessment;
  findings: Finding[];
  domainIntel?: DomainIntelligence;
  graphData?: ThreatGraphData;
  geolocation?: GeolocationData;
  aiSummary?: string;
  aiRecommendations?: string[];
  aiAnalysis?: Record<string, AIThreatAnalysis>;
}

// AI Threat Analyst & Gemini Types
export interface AIKeyFinding {
  title: string;
  explanation: string;
  evidence: string[];
  source: string;
  confidence: string;
  uncertainty: string;
}

export interface AIRecommendedAction {
  priority: 'Immediate' | 'Short-term' | 'Preventive' | string;
  title: string;
  reason: string;
  expected_benefit?: string;
  steps: string[];
  evidence_refs: string[];
}

export interface AIThreatAnalysis {
  investigation_id: string;
  language: string;
  executive_summary: string;
  risk_level: string;
  risk_score: number | null;
  confidence: string;
  risk_classification_explanation: string;
  key_findings: AIKeyFinding[];
  recommended_actions: AIRecommendedAction[];
  safe_practices: string[];
  actions_to_avoid: string[];
  false_positive_analysis: string;
  technical_explanation: string;
  limitations: string[];
  is_ai_generated: boolean;
  model_used: string;
}

export interface AIChatMessage {
  role: 'user' | 'assistant' | 'model';
  content: string;
  timestamp?: string;
}

export interface AIChatResponseData {
  investigation_id: string;
  response: string;
  language: string;
  source: string;
  is_ai_generated: boolean;
}

// Domain / network intelligence
export interface DomainIntelligence {
  dns: DNSRecord[];
  whois: WhoisData;
  ssl: SSLCertificate;
  ipInfo: IPInfo;
  reputation: ReputationData;
  geo?: GeolocationData;
}

export interface DNSRecord {
  type: string;   // A, AAAA, MX, NS, TXT, CNAME
  name: string;
  value: string;
  ttl: number;
}

export interface WhoisData {
  registrar: string;
  createdDate: string;
  expiryDate: string;
  updatedDate: string;
  registrant: string;
  nameServers: string[];
  status: string[];
}

export interface SSLCertificate {
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  protocol: string;
  keyExchange: string;
  cipher: string;
  isValid: boolean;
}

export interface IPInfo {
  ip: string;
  asn: string;
  org: string;
  country: string;
  city: string;
  isp: string;
  isProxy: boolean;
  isTor: boolean;
  isVPN: boolean;
  latitude?: number;
  longitude?: number;
  region?: string;
  countryCode?: string;
  source?: string;
}

export interface ReputationData {
  score: number;         // 0–100
  malicious: boolean;
  sources: ReputationSource[];
  categories: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface ReputationSource {
  name: string;
  result: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  detail?: string;
}

// Threat graph (D3) types
export interface ThreatGraphNode {
  id: string;
  label: string;
  type: 'indicator' | 'ip' | 'domain' | 'url' | 'hash' | 'report' | 'actor' | 'malware' | 'campaign' | 'vulnerability' | 'infrastructure';
  risk: Severity;
  details?: Record<string, string>;
}

export interface ThreatGraphLink {
  source: string;
  target: string;
  relationship: string;
  confidence: number;
}

export interface ThreatGraphData {
  nodes: ThreatGraphNode[];
  links: ThreatGraphLink[];
}

// Alert
export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  indicator?: string;
  message: string;
  source: string;
  timestamp: string;
  read: boolean;
  investigationId?: string;
}

// Dashboard stats
export interface DashboardStats {
  totalInvestigations: number;
  activeScans: number;
  criticalFindings: number;
  avgRiskScore: number;
  findingsBySeverity: Record<Severity, number>;
}
