import type { ThreatGraphData } from './types';

export function createInvestigationGraphData(): ThreatGraphData {
  return {
    nodes: [
      {
        id: 'domain-a',
        label: 'suspicious-domain.test',
        type: 'domain',
        risk: 'high',
        details: {
          registrar: 'NameCheap Inc.',
          firstSeen: '2024-12-20',
          asn: 'AS64496',
          category: 'C2 Rendezvous Point',
        },
      },
      {
        id: 'ip-a',
        label: '192.0.2.1',
        type: 'ip',
        risk: 'critical',
        details: {
          network: 'TEST-NET-1 (64496)',
          location: 'Frankfurt, DE',
          ports: '443, 4444, 8080',
          feedMatch: 'AlienVault OTX, Abuse.ch',
        },
      },
      {
        id: 'ip-b',
        label: '198.51.100.23',
        type: 'ip',
        risk: 'critical',
        details: {
          network: 'TEST-NET-2 (64500)',
          location: 'Amsterdam, NL',
          ports: '80, 443, 9001',
          role: 'Active C2 Controller & Exfil Gateway',
        },
      },
      {
        id: 'domain-b',
        label: 'phishing-login.test',
        type: 'domain',
        risk: 'high',
        details: {
          registrar: 'DomainShield Ltd',
          created: '2025-01-13',
          sslSubject: 'CN=*.example.test (Mismatch)',
          target: 'Corporate SSO Portal',
        },
      },
      {
        id: 'url-a',
        label: 'https://phishing-login.test/sign-in',
        type: 'url',
        risk: 'high',
        details: {
          path: '/sign-in',
          method: 'Credential Harvester Form',
          redirect: 'POST 198.51.100.23/gate.php',
        },
      },
      {
        id: 'hash-a',
        label: 'e3b0c442...991b7852',
        type: 'hash',
        risk: 'critical',
        details: {
          algorithm: 'SHA-256',
          classification: 'LockBit 3.0 Dropper Variant',
          detectionRatio: '54/70 AV Engines',
        },
      },
      {
        id: 'actor-a',
        label: 'APT-29 / Midnight Blizzard',
        type: 'actor',
        risk: 'critical',
        details: {
          attributionConfidence: '82%',
          ttps: 'T1566.002, T1071.001, T1059.001',
          objective: 'Credential Theft & C2 Establishment',
        },
      },
      {
        id: 'email-a',
        label: 'phisher@covert-campaign.test',
        type: 'indicator',
        risk: 'high',
        details: {
          role: 'Spear-phishing lure sender',
          spf: 'Fail',
          dmarc: 'Reject',
          lureTopic: 'Urgent Wire Transfer Authorization',
        },
      },
      {
        id: 'report-a',
        label: 'Threat Advisory TN-2025-042',
        type: 'report',
        risk: 'medium',
        details: {
          advisoryId: 'TN-2025-042',
          source: 'ThreatNova AI Early-Warning Core',
          severity: 'Elevated Threat Cluster',
        },
      },
      {
        id: 'domain-c',
        label: 'clean-example.test',
        type: 'domain',
        risk: 'low',
        details: {
          registrar: 'MarkMonitor Inc.',
          status: 'Legitimate Corporate Domain',
          reputation: 'Clean (0/90 engines)',
        },
      },
      {
        id: 'url-b',
        label: 'https://clean-example.test/',
        type: 'url',
        risk: 'low',
        details: {
          path: '/',
          status: '200 OK',
          securityHeaders: 'HSTS, CSP, X-Frame-Options Present',
        },
      },
    ],
    links: [
      { source: 'domain-a', target: 'ip-a', relationship: 'DNS A record', confidence: 96 },
      { source: 'domain-a', target: 'ip-b', relationship: 'secondary routing', confidence: 78 },
      { source: 'actor-a', target: 'domain-a', relationship: 'attributed campaign', confidence: 84 },
      { source: 'actor-a', target: 'email-a', relationship: 'operates lure persona', confidence: 79 },
      { source: 'email-a', target: 'domain-b', relationship: 'hyperlinks in body', confidence: 94 },
      { source: 'domain-b', target: 'url-a', relationship: 'hosts landing page', confidence: 98 },
      { source: 'url-a', target: 'ip-b', relationship: 'data exfiltration relay', confidence: 91 },
      { source: 'hash-a', target: 'ip-a', relationship: 'beacons to C2', confidence: 89 },
      { source: 'hash-a', target: 'report-a', relationship: 'indexed in advisory', confidence: 95 },
      { source: 'report-a', target: 'actor-a', relationship: 'profiles threat actor', confidence: 86 },
      { source: 'domain-c', target: 'url-b', relationship: 'hosts valid homepage', confidence: 99 },
    ],
  };
}
