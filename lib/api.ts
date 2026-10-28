// lib/api.ts
// ThreatNova AI - Centralized Backend API Client for FastAPI backend.
// Configured to communicate with process.env.NEXT_PUBLIC_API_BASE_URL (defaults to http://localhost:8000)

import type {
  AIChatMessage,
  AIChatResponseData,
  AIThreatAnalysis,
  Alert,
  Finding,
  IndicatorType,
  Investigation,
  ThreatGraphData,
} from './types';

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

export interface BackendHealth {
  status: string;
  version: string;
  database: string;
  virustotalConfigured: boolean;
  llmConfigured: boolean;
  llmProvider: string;
  timestamp: string;
}

export interface AnalysisResult {
  investigationId: string;
  indicator: string;
  indicatorType: IndicatorType;
  summary: string;
  explanation: string;
  recommendations: string[];
  source: string;
  isAiGenerated: boolean;
}

export interface QuickLookupResult {
  indicator: string;
  type: string;
  valid: boolean;
  reputation: {
    malicious: boolean;
    positives: number;
    total: number;
    status: string;
    isDemo: boolean;
    categories: string[];
  };
  network: {
    resolvedIp?: string;
    asn?: string;
    country?: string;
    city?: string;
    region?: string;
    isTor: boolean;
    isProxy: boolean;
    isVPN: boolean;
  };
}

/**
 * Check backend service connectivity and configuration health.
 */
export async function checkBackendHealth(): Promise<BackendHealth | null> {
  try {
    const res = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    if (!res.ok) return null;
    return (await res.json()) as BackendHealth;
  } catch (error) {
    console.debug('ThreatNova AI backend is offline or unreachable:', error);
    return null;
  }
}

/**
 * Fetch investigations list from backend SQLite database.
 */
export async function fetchInvestigations(
  limit: number = 20,
  offset: number = 0,
  type?: string,
  q?: string
): Promise<Investigation[]> {
  const params = new URLSearchParams({ limit: String(limit), skip: String(offset) });
  if (type && type !== 'all') params.set('type', type);
  if (q && q.trim()) params.set('q', q.trim());

  const res = await fetch(
    `${API_BASE_URL}/api/investigations?${params.toString()}`,
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch investigations: ${res.statusText}`);
  }
  return (await res.json()) as Investigation[];
}

/**
 * Fetch a specific investigation by ID with full graph and findings.
 */
export async function fetchInvestigation(
  id: string
): Promise<Investigation | null> {
  const res = await fetch(`${API_BASE_URL}/api/investigations/${id}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation ${id}: ${res.statusText}`);
  }
  return (await res.json()) as Investigation;
}

/**
 * Submit and trigger an autonomous threat investigation on an indicator.
 */
export async function createInvestigation(
  query: string,
  type?: IndicatorType
): Promise<Investigation> {
  const res = await fetch(`${API_BASE_URL}/api/investigations`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ query, type }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(
      errorData.detail || `Failed to create investigation: ${res.statusText}`
    );
  }
  return (await res.json()) as Investigation;
}

/**
 * Fetch D3 force-directed threat graph nodes and links for an investigation.
 */
export async function fetchInvestigationGraph(
  id: string
): Promise<ThreatGraphData> {
  const res = await fetch(`${API_BASE_URL}/api/investigations/${id}/graph`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch threat graph for ${id}: ${res.statusText}`);
  }
  return (await res.json()) as ThreatGraphData;
}

/**
 * Fetch AI executive summary and defensive recommendations for an investigation.
 */
export async function fetchInvestigationAnalysis(
  id: string
): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE_URL}/api/investigations/${id}/analysis`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(
      `Failed to fetch threat analysis for ${id}: ${res.statusText}`
    );
  }
  return (await res.json()) as AnalysisResult;
}

/**
 * Delete an investigation from backend database.
 */
export async function deleteInvestigation(id: string): Promise<boolean> {
  const res = await fetch(`${API_BASE_URL}/api/investigations/${id}`, {
    method: 'DELETE',
    headers: { Accept: 'application/json' },
  });
  return res.ok;
}

/**
 * Quick indicator inspection and validation lookup.
 */
export async function quickLookupIndicator(
  type: IndicatorType,
  value: string
): Promise<QuickLookupResult> {
  const res = await fetch(
    `${API_BASE_URL}/api/indicators/${type}/${encodeURIComponent(value)}`,
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
    }
  );
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(
      errorData.detail || `Failed to lookup indicator: ${res.statusText}`
    );
  }
  return (await res.json()) as QuickLookupResult;
}

/**
 * Generate structured Gemini AI Threat Analyst report.
 */
export async function analyzeInvestigationWithAI(
  investigationId: string,
  language: string = 'en',
  investigationData?: any
): Promise<AIThreatAnalysis> {
  const res = await fetch(`${API_BASE_URL}/api/ai/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      investigation_id: investigationId,
      language,
      investigation_data: investigationData,
    }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(
      errorData.detail || `Failed to analyze with AI: ${res.statusText}`
    );
  }

  return (await res.json()) as AIThreatAnalysis;
}

/**
 * Interactive context-aware chat with the AI Threat Analyst.
 */
export async function chatWithAIAnalyst(
  investigationId: string,
  message: string,
  language: string = 'en',
  history: AIChatMessage[] = [],
  investigationData?: any
): Promise<AIChatResponseData> {
  const res = await fetch(`${API_BASE_URL}/api/ai/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      investigation_id: investigationId,
      message,
      language,
      history,
      investigation_data: investigationData,
    }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(
      errorData.detail || `Failed to chat with AI Analyst: ${res.statusText}`
    );
  }

  return (await res.json()) as AIChatResponseData;
}

/**
 * Check AI status and active Gemini model configuration.
 */
export async function getAIStatus(): Promise<{
  status: string;
  gemini_configured: boolean;
  model: string;
  mode: string;
  provider: string;
  sdk: string;
  description: string;
} | null> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/ai/status`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.debug('Failed to fetch AI status:', err);
    return null;
  }
}

export interface DashboardStats {
  totalInvestigations: number;
  completedInvestigations: number;
  activeScans: number;
  highRiskAlerts: number;
  correlatedEntities: number;
  findingsBySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

/**
 * Fetch aggregated scoreboard metrics directly from persisted SQLite database.
 */
export async function fetchDashboardStats(): Promise<DashboardStats | null> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/investigations/stats`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    if (!res.ok) return null;
    return (await res.json()) as DashboardStats;
  } catch (err) {
    console.debug('Failed to fetch dashboard stats from backend:', err);
    return null;
  }
}

/**
 * Fetch forensic findings and evidence records from SQLite.
 */
export async function fetchFindings(
  severity?: string,
  category?: string,
  limit: number = 100,
  offset: number = 0
): Promise<Finding[]> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (severity && severity !== 'all') params.set('severity', severity);
  if (category && category !== 'all') params.set('category', category);

  const res = await fetch(`${API_BASE_URL}/api/findings?${params.toString()}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch findings: ${res.statusText}`);
  }
  return (await res.json()) as Finding[];
}

/**
 * Fetch actionable threat alerts from SQLite.
 */
export async function fetchAlerts(
  severity?: string,
  limit: number = 50,
  offset: number = 0
): Promise<Alert[]> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (severity && severity !== 'all') params.set('severity', severity);

  const res = await fetch(`${API_BASE_URL}/api/alerts?${params.toString()}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts: ${res.statusText}`);
  }
  return (await res.json()) as Alert[];
}

/**
 * Quick indicator validation and live network intelligence lookup.
 */
export async function fetchQuickLookup(
  type: string,
  value: string
): Promise<QuickLookupResult | null> {
  try {
    const res = await fetch(
      `${API_BASE_URL}/api/indicators/${encodeURIComponent(type.toLowerCase())}/${encodeURIComponent(value.trim())}`,
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
      }
    );
    if (!res.ok) return null;
    return (await res.json()) as QuickLookupResult;
  } catch (err) {
    console.debug('Failed quick lookup:', err);
    return null;
  }
}
