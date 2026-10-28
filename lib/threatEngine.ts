export type QueryType = 'email' | 'domain' | 'url' | 'ip' | 'unknown';

export interface ThreatFactor {
  name: string;
  pts: number;
  description: string;
}

export interface DynamicThreatScore {
  score: number;
  confidence: number;
  level: 'critical' | 'high' | 'medium' | 'low';
  factors: ThreatFactor[];
  explanation: string;
}

/**
 * Detect indicator query type:
 * - email if contains @
 * - ip if regex /^\d+\.\d+\.\d+\.\d+$/
 * - url if startsWith http
 * - domain otherwise
 */
export function detectType(q: string): QueryType {
  if (!q || typeof q !== 'string') return 'unknown';
  const trimmed = q.trim();
  if (!trimmed) return 'unknown';
  if (trimmed.includes('@')) return 'email';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) return 'ip';
  if (
    trimmed.toLowerCase().startsWith('http://') ||
    trimmed.toLowerCase().startsWith('https://') ||
    trimmed.toLowerCase().startsWith('http')
  ) {
    return 'url';
  }
  return 'domain';
}

export const MOCK_SCORES: Record<QueryType, DynamicThreatScore> = {
  email: {
    score: 62,
    confidence: 78,
    level: 'medium',
    factors: [
      { name: 'Disposable Email', pts: 25, description: 'Provider flagged on temporary inbox lists' },
      { name: 'Breach Match', pts: 20, description: 'Exposed in credential stuffing datasets' },
      { name: 'Recent Creation', pts: 10, description: 'Domain registered within last 30 days' },
      { name: 'Suspicious TLD', pts: 7, description: 'Elevated abuse rate on top-level domain' },
    ],
    explanation: 'Email indicator correlates with known breach databases and non-standard MX routing.',
  },
  domain: {
    score: 78,
    confidence: 85,
    level: 'high',
    factors: [
      { name: 'Threat Intelligence Feeds', pts: 35, description: 'Listed on 3 commercial intelligence blacklists' },
      { name: 'Fast Flux DNS', pts: 20, description: 'Rapid IP changes detected in passive DNS history' },
      { name: 'Certificate Anomaly', pts: 10, description: 'Self-signed certificate with mismatched hostname' },
      { name: 'Suspicious Ports', pts: 8, description: 'Non-standard ports associated with RATs' },
      { name: 'Registrar History', pts: 5, description: 'Registrar known for slow abuse takedown response' },
    ],
    explanation: 'Autonomous correlation identified coordinated infrastructure patterns matching known C2 operations with 85% statistical confidence.',
  },
  url: {
    score: 91,
    confidence: 92,
    level: 'critical',
    factors: [
      { name: 'Phishing Pattern', pts: 40, description: 'Structural similarity to known banking login page' },
      { name: 'IDN Homograph', pts: 25, description: 'Cyrillic character substitution in authority domain' },
      { name: 'Shortened URL', pts: 15, description: 'Multi-hop redirect chain masking destination payload' },
      { name: 'Blacklisted', pts: 11, description: 'Flagged by anti-phishing telemetry feeds' },
    ],
    explanation: 'URL exhibits weaponized credential interception patterns with active redirect chains and high likelihood of credential harvest.',
  },
  ip: {
    score: 45,
    confidence: 65,
    level: 'medium',
    factors: [
      { name: 'Tor Exit Node', pts: 20, description: 'Active proxy routing node on privacy networks' },
      { name: 'Abuse Reports', pts: 15, description: 'Elevated scanning activity logged in past 48h' },
      { name: 'Geo Mismatch', pts: 10, description: 'BGP announcement does not match ASN origin' },
    ],
    explanation: 'IP address shows intermediate proxy routing and recurring scanning activity without confirmed host exploitation.',
  },
  unknown: {
    score: 34,
    confidence: 50,
    level: 'low',
    factors: [
      { name: 'Unclassified Pattern', pts: 15, description: 'Heuristic classification inconclusive' },
      { name: 'Low Telemetry Coverage', pts: 10, description: 'Limited observational history in local fixtures' },
      { name: 'Baseline Heuristics', pts: 9, description: 'Default risk weighting applied' },
    ],
    explanation: 'Indicator did not match known structured signatures. Baseline low-confidence score assigned.',
  },
};
