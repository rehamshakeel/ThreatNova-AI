import type {
  Finding,
  Investigation,
  InvestigationInput,
  RiskAssessment,
} from '@/lib/types';

/**
 * Repository interface for persistent storage (e.g. SQLite via FastAPI)
 */
export interface InvestigationRepository {
  list(): Promise<Investigation[]>;
  getById(id: string): Promise<Investigation | null>;
  save(investigation: Investigation): Promise<void>;
  delete(id: string): Promise<void>;
}

/**
 * Provider interface for multi-source enrichment (DNS, WHOIS, IP Geolocation)
 */
export interface IndicatorEnrichmentProvider {
  enrich(input: InvestigationInput): Promise<Partial<Investigation>>;
}

/**
 * VirusTotal API Provider contract (executed on backend only)
 */
export interface VirusTotalLookupProvider {
  lookupIndicator(indicator: string, type: string): Promise<{
    detectionRatio: string;
    positives: number;
    total: number;
    engines: Record<string, { category: string; result: string | null }>;
  }>;
}

/**
 * LLM Reasoning Provider contract for autonomous threat summarization
 */
export interface LLMReasoningProvider {
  explainFindings(findings: Finding[]): Promise<string>;
  assessRisk(indicator: string, evidence: Finding[]): Promise<RiskAssessment>;
}

/**
 * Backend Client Configuration
 */
export interface FastAPIClientConfig {
  baseUrl: string;
  timeoutMs: number;
  apiKeyHeader?: string;
}

export type IntegrationState = 'not-configured' | 'ready' | 'simulated' | 'error';
