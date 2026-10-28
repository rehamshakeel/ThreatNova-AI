// lib/demo-data.ts
// Clearly labelled demonstration data — not real threat intelligence

import type {
  Investigation, Finding, RiskAssessment, Severity,
  DomainIntelligence,
  Alert, DashboardStats,
} from './types';

// ── Demo Findings ──
export function createDemoFindings(): Finding[] {
  const findings: Finding[] = [
    {
      id: 'f1',
      title: 'Known Command & Control Server',
      severity: 'critical',
      category: 'Threat Intelligence',
      description: 'This IP address has been identified in multiple threat intelligence feeds as a known C2 server associated with APT-29 activity. [DEMONSTRATION DATA]',
      evidence: [
        { type: 'log', label: 'ThreatFeed Match', content: 'Matched in 3/7 threat feeds: AlienVault OTX, Abuse.ch, CIRCL' },
        { type: 'network', label: 'Network Pattern', content: 'Beacon-like traffic pattern: 60s intervals, 256-byte payloads, encrypted channel' },
      ],
      timestamp: '2025-01-15T14:32:00Z',
      source: 'Threat Intelligence Module',
    },
    {
      id: 'f2',
      title: 'Suspicious SSL Certificate',
      severity: 'high',
      category: 'Certificate Analysis',
      description: 'SSL certificate uses a self-signed CA with a validity period of 10 years, which is unusual for legitimate services. Certificate subject does not match the domain. [DEMONSTRATION DATA]',
      evidence: [
        { type: 'certificate', label: 'Certificate Details', content: 'Issuer: CN=Unknown CA, O=-, Subject: CN=*.example.test, Valid: 2020-2030' },
        { type: 'dns', label: 'Domain Mismatch', content: 'Certificate CN *.example.test does not match queried domain' },
      ],
      timestamp: '2025-01-15T14:33:00Z',
      source: 'SSL Analysis Module',
    },
    {
      id: 'f3',
      title: 'Domain Registered Recently',
      severity: 'medium',
      category: 'WHOIS Analysis',
      description: 'The domain was registered less than 30 days ago, which is common among phishing and malware distribution domains. [DEMONSTRATION DATA]',
      evidence: [
        { type: 'whois', label: 'Registration Date', content: 'Created: 2024-12-20, Registrar: NameCheap, Privacy protection enabled' },
      ],
      timestamp: '2025-01-15T14:31:00Z',
      source: 'WHOIS Module',
    },
    {
      id: 'f4',
      title: 'Open Ports with Uncommon Services',
      severity: 'medium',
      category: 'Port Analysis',
      description: 'Multiple non-standard ports are open running services commonly associated with remote access tools. [DEMONSTRATION DATA]',
      evidence: [
        { type: 'network', label: 'Port Scan Results', content: 'Open: 443 (HTTPS), 4444 (Metasploit default), 8080 (HTTP-Proxy), 9001 (Tor)' },
      ],
      timestamp: '2025-01-15T14:34:00Z',
      source: 'Port Scanner Module',
    },
    {
      id: 'f5',
      title: 'Associated with Tor Exit Node',
      severity: 'low',
      category: 'Network Intelligence',
      description: 'This IP address has been previously recorded as a Tor exit node. While not inherently malicious, this indicates potential anonymisation. [DEMONSTRATION DATA]',
      evidence: [
        { type: 'network', label: 'Tor Project Data', content: 'Listed in Tor exit node directory. Last seen: 2025-01-10' },
      ],
      timestamp: '2025-01-15T14:35:00Z',
      source: 'Network Intelligence Module',
    },
    {
      id: 'f6',
      title: 'DNS Configuration Normal',
      severity: 'info',
      category: 'DNS Analysis',
      description: 'DNS records are properly configured with standard TTL values. No DNS tunneling indicators detected. [DEMONSTRATION DATA]',
      evidence: [
        { type: 'dns', label: 'DNS Records', content: 'A: 192.0.2.1 (TTL 300), MX: mail.example.test (TTL 3600), NS: ns1.registrar.test' },
      ],
      timestamp: '2025-01-15T14:30:00Z',
      source: 'DNS Module',
    },
  ];

  const confidence = [82, 76, 71, 68, 64, 88];
  const relatedIndicators = [
    ['192.0.2.1', 'suspicious-domain.test'],
    ['suspicious-domain.test', 'certificate sample'],
    ['phishing-login.test', 'suspicious-domain.test'],
    ['192.0.2.1', 'port 4444'],
    ['192.0.2.50', 'sample network'],
    ['suspicious-domain.test'],
  ];

  return findings.map((finding, index) => ({
    ...finding,
    confidence: confidence[index],
    relatedIndicators: relatedIndicators[index],
  }));
}

// ── Demo Risk Assessment ──
export function createDemoRisk(): RiskAssessment {
  return {
    score: 78,
    level: 'high',
    confidence: 85,
    factors: [
      { name: 'Threat Intel Match', impact: 35, description: 'Matched in multiple threat intelligence feeds' },
      { name: 'Certificate Anomaly', impact: 20, description: 'Self-signed certificate with domain mismatch' },
      { name: 'Recent Registration', impact: 10, description: 'Domain registered within the last 30 days' },
      { name: 'Suspicious Ports', impact: 8, description: 'Non-standard ports associated with RATs' },
      { name: 'Tor Association', impact: 5, description: 'Previously listed as Tor exit node' },
    ],
    explanation: 'Risk Score reflects the aggregated weighted severity of findings. This is not a confidence score — a high risk score means the indicator exhibits multiple traits commonly associated with malicious infrastructure. Confidence (85%) indicates how many data sources corroborated these findings. [DEMONSTRATION DATA — does not represent real threat assessment]',
  };
}

// ── Demo Domain Intelligence ──
export function createDemoDomainIntel(): DomainIntelligence {
  return {
    dns: [
      { type: 'A', name: 'suspicious-domain.test', value: '192.0.2.1', ttl: 300 },
      { type: 'AAAA', name: 'suspicious-domain.test', value: '2001:db8::1', ttl: 300 },
      { type: 'MX', name: 'suspicious-domain.test', value: 'mail.suspicious-domain.test', ttl: 3600 },
      { type: 'NS', name: 'suspicious-domain.test', value: 'ns1.registrar.test', ttl: 86400 },
      { type: 'NS', name: 'suspicious-domain.test', value: 'ns2.registrar.test', ttl: 86400 },
      { type: 'TXT', name: 'suspicious-domain.test', value: 'v=spf1 ~all', ttl: 3600 },
    ],
    whois: {
      registrar: 'NameCheap Inc.',
      createdDate: '2024-12-20T00:00:00Z',
      expiryDate: '2025-12-20T00:00:00Z',
      updatedDate: '2024-12-20T00:00:00Z',
      registrant: 'REDACTED FOR PRIVACY',
      nameServers: ['ns1.registrar.test', 'ns2.registrar.test'],
      status: ['clientTransferProhibited'],
    },
    ssl: {
      issuer: 'CN=Unknown CA, O=Self-Signed',
      subject: 'CN=*.example.test',
      validFrom: '2020-01-01T00:00:00Z',
      validTo: '2030-01-01T00:00:00Z',
      serialNumber: '0A:1B:2C:3D:4E:5F:6A:7B',
      fingerprint: 'SHA256:a1b2c3d4e5f6...',
      protocol: 'TLS 1.2',
      keyExchange: 'ECDHE_RSA',
      cipher: 'AES_256_GCM',
      isValid: false,
    },
    ipInfo: {
      ip: '192.0.2.1',
      asn: 'AS64496',
      org: 'Example Hosting Ltd.',
      country: 'RO',
      city: 'Bucharest',
      isp: 'Example Hosting',
      isProxy: false,
      isTor: true,
      isVPN: false,
    },
    reputation: {
      score: 22,
      malicious: true,
      sources: [
        { name: 'VirusTotal', result: 'malicious', detail: '5/90 engines flagged' },
        { name: 'AlienVault OTX', result: 'malicious', detail: 'Found in 3 pulses' },
        { name: 'AbuseIPDB', result: 'suspicious', detail: 'Confidence: 67%' },
        { name: 'Shodan', result: 'suspicious', detail: '4 open ports' },
        { name: 'Google Safe Browsing', result: 'clean' },
        { name: 'PhishTank', result: 'clean' },
      ],
      categories: ['C2 Server', 'Malware Distribution'],
      firstSeen: '2024-06-15T00:00:00Z',
      lastSeen: '2025-01-14T00:00:00Z',
    },
  };
}

// ── Multi-Indicator Demo Intelligence Helper ──
export function getDemoDomainIntel(indicator?: string): DomainIntelligence {
  const norm = (indicator || '').trim().toLowerCase();

  if (norm.includes('198.51.100.23') || norm.includes('192.0.2.') || norm.includes('198.51.')) {
    return {
      dns: [
        { type: 'PTR', name: '23.100.51.198.in-addr.arpa', value: 'c2-gateway-01.threatnet.test', ttl: 1800 },
        { type: 'A', name: 'c2-gateway-01.threatnet.test', value: '198.51.100.23', ttl: 300 },
        { type: 'TXT', name: 'c2-gateway-01.threatnet.test', value: 'security-contact=abuse@threatnet.test', ttl: 3600 },
      ],
      whois: {
        registrar: 'ARIN Direct Allocation',
        createdDate: '2021-03-14T00:00:00Z',
        expiryDate: '2026-03-14T00:00:00Z',
        updatedDate: '2024-11-01T00:00:00Z',
        registrant: 'ThreatNet Hosting Infrastructure Ltd.',
        nameServers: ['auth1.threatnet.test', 'auth2.threatnet.test'],
        status: ['active', 'allocated-non-portable'],
      },
      ssl: {
        issuer: 'CN=ThreatNet Internal CA, O=Untrusted',
        subject: 'CN=c2-node-relay.internal',
        validFrom: '2023-01-15T00:00:00Z',
        validTo: '2033-01-15T00:00:00Z',
        serialNumber: '7F:2E:4A:9C:11:3D',
        fingerprint: 'SHA256:d8e9f0a1b2c3...',
        protocol: 'TLS 1.3',
        keyExchange: 'X25519',
        cipher: 'CHACHA20_POLY1305_SHA256',
        isValid: false,
      },
      ipInfo: {
        ip: norm || '198.51.100.23',
        asn: 'AS64496',
        org: 'ThreatNet Autonomous System',
        country: 'NL',
        city: 'Amsterdam',
        isp: 'ThreatNet Server Colocation',
        isProxy: true,
        isTor: true,
        isVPN: true,
      },
      reputation: {
        score: 18,
        malicious: true,
        sources: [
          { name: 'VirusTotal', result: 'malicious', detail: '7/90 security vendors flagged IP' },
          { name: 'AbuseIPDB', result: 'malicious', detail: 'Reported 142 times for brute-force' },
          { name: 'AlienVault OTX', result: 'malicious', detail: '4 malicious threat pulses' },
          { name: 'Shodan', result: 'suspicious', detail: 'Ports 22, 443, 4444 open' },
          { name: 'Spamhaus EDROP', result: 'malicious', detail: 'Listed in drop list' },
          { name: 'Google Safe Browsing', result: 'clean' },
        ],
        categories: ['C2 Gateway', 'Tor Relay', 'Brute-force Scanner'],
        firstSeen: '2023-09-10T00:00:00Z',
        lastSeen: '2025-01-15T00:00:00Z',
      },
    };
  }

  if (norm.includes('dark-stealer') || norm.includes('phishing')) {
    return {
      dns: [
        { type: 'A', name: 'dark-stealer-c2.net', value: '198.51.100.23', ttl: 120 },
        { type: 'CNAME', name: 'login.dark-stealer-c2.net', value: 'dark-stealer-c2.net', ttl: 120 },
        { type: 'MX', name: 'dark-stealer-c2.net', value: 'mail.dark-stealer-c2.net', ttl: 3600 },
        { type: 'NS', name: 'dark-stealer-c2.net', value: 'dns1.bulletproof-dns.org', ttl: 86400 },
      ],
      whois: {
        registrar: 'Tucows Domains Inc.',
        createdDate: '2025-01-08T00:00:00Z',
        expiryDate: '2026-01-08T00:00:00Z',
        updatedDate: '2025-01-08T00:00:00Z',
        registrant: 'Contact Privacy Inc. Customer 016482',
        nameServers: ['dns1.bulletproof-dns.org', 'dns2.bulletproof-dns.org'],
        status: ['clientTransferProhibited', 'serverHold'],
      },
      ssl: {
        issuer: "CN=Let's Encrypt Authority X3, O=Let's Encrypt",
        subject: 'CN=dark-stealer-c2.net',
        validFrom: '2025-01-08T00:00:00Z',
        validTo: '2025-04-08T00:00:00Z',
        serialNumber: '03:8A:2F:11:9B:4C',
        fingerprint: 'SHA256:4c2f8a119b4c...',
        protocol: 'TLS 1.3',
        keyExchange: 'ECDHE_RSA',
        cipher: 'AES_128_GCM_SHA256',
        isValid: true,
      },
      ipInfo: {
        ip: '198.51.100.23',
        asn: 'AS49505',
        org: 'Bulletproof Hosting B.V.',
        country: 'NL',
        city: 'Haarlem',
        isp: 'Offshore Cloud NV',
        isProxy: true,
        isTor: false,
        isVPN: false,
      },
      reputation: {
        score: 14,
        malicious: true,
        sources: [
          { name: 'VirusTotal', result: 'malicious', detail: '8/90 engines detected phishing' },
          { name: 'PhishTank', result: 'malicious', detail: 'Verified active phishing site' },
          { name: 'Google Safe Browsing', result: 'malicious', detail: 'Social engineering flagged' },
          { name: 'AlienVault OTX', result: 'malicious', detail: 'Associated with Infostealer' },
          { name: 'AbuseIPDB', result: 'suspicious', detail: 'Confidence 45%' },
        ],
        categories: ['Credential Phishing', 'Stealer C2'],
        firstSeen: '2025-01-08T00:00:00Z',
        lastSeen: '2025-01-15T00:00:00Z',
      },
    };
  }

  if (norm.includes('clean') || norm.includes('safe')) {
    return {
      dns: [
        { type: 'A', name: 'safe-cdn.test', value: '104.21.45.12', ttl: 300 },
        { type: 'AAAA', name: 'safe-cdn.test', value: '2606:4700:3037::6815:2d0c', ttl: 300 },
        { type: 'NS', name: 'safe-cdn.test', value: 'dora.ns.cloudflare.com', ttl: 86400 },
        { type: 'NS', name: 'safe-cdn.test', value: 'walt.ns.cloudflare.com', ttl: 86400 },
        { type: 'TXT', name: 'safe-cdn.test', value: 'v=spf1 include:_spf.google.com ~all', ttl: 3600 },
      ],
      whois: {
        registrar: 'Cloudflare, Inc.',
        createdDate: '2018-05-12T00:00:00Z',
        expiryDate: '2028-05-12T00:00:00Z',
        updatedDate: '2024-04-20T00:00:00Z',
        registrant: 'Verified Enterprise Entity',
        nameServers: ['dora.ns.cloudflare.com', 'walt.ns.cloudflare.com'],
        status: ['clientTransferProhibited'],
      },
      ssl: {
        issuer: 'CN=DigiCert Global Root G2, O=DigiCert Inc',
        subject: 'CN=*.safe-cdn.test',
        validFrom: '2024-01-01T00:00:00Z',
        validTo: '2025-01-01T00:00:00Z',
        serialNumber: '4A:7C:1E:88:52:90',
        fingerprint: 'SHA256:1e8852904a7c...',
        protocol: 'TLS 1.3',
        keyExchange: 'X25519',
        cipher: 'AES_256_GCM_SHA384',
        isValid: true,
      },
      ipInfo: {
        ip: '104.21.45.12',
        asn: 'AS13335',
        org: 'Cloudflare, Inc.',
        country: 'US',
        city: 'San Francisco',
        isp: 'Cloudflare Managed Anycast',
        isProxy: false,
        isTor: false,
        isVPN: false,
      },
      reputation: {
        score: 95,
        malicious: false,
        sources: [
          { name: 'VirusTotal', result: 'clean', detail: '0/90 security engines flagged' },
          { name: 'Google Safe Browsing', result: 'clean' },
          { name: 'PhishTank', result: 'clean' },
          { name: 'AlienVault OTX', result: 'clean' },
          { name: 'AbuseIPDB', result: 'clean' },
        ],
        categories: ['CDN', 'Legitimate Infrastructure'],
        firstSeen: '2018-06-01T00:00:00Z',
        lastSeen: '2025-01-15T00:00:00Z',
      },
    };
  }

  return createDemoDomainIntel();
}

// ── Demo Alerts ──
export function createDemoAlerts(): Alert[] {
  return [
    {
      id: 'a1',
      title: 'Critical: New C2 Infrastructure Detected',
      severity: 'critical',
      indicator: '192.0.2.1',
      message: 'A new command and control server has been identified at 192.0.2.1. This IP matches known APT-29 infrastructure patterns. Immediate investigation recommended. [DEMONSTRATION DATA]',
      source: 'Threat Intelligence',
      timestamp: '2025-01-15T14:32:00Z',
      read: false,
      investigationId: 'inv-001',
    },
    {
      id: 'a2',
      title: 'High: Phishing Domain Registered',
      severity: 'high',
      indicator: 'phishing-login.test',
      message: 'Domain phishing-login.test was registered 2 days ago using privacy protection. It mimics a known financial institution login page. [DEMONSTRATION DATA]',
      source: 'Domain Monitoring',
      timestamp: '2025-01-15T12:15:00Z',
      read: false,
    },
    {
      id: 'a3',
      title: 'Medium: Unusual Port Activity',
      severity: 'medium',
      indicator: '192.0.2.1',
      message: 'Port 4444 (commonly used by Metasploit) detected open on infrastructure associated with ongoing investigation. [DEMONSTRATION DATA]',
      source: 'Port Scanner',
      timestamp: '2025-01-15T10:45:00Z',
      read: true,
      investigationId: 'inv-001',
    },
    {
      id: 'a4',
      title: 'Low: SSL Certificate Expiring',
      severity: 'low',
      indicator: 'example-monitor.test',
      message: 'SSL certificate for monitored domain example-monitor.test expires in 14 days. Consider renewal to maintain monitoring coverage. [DEMONSTRATION DATA]',
      source: 'Certificate Monitor',
      timestamp: '2025-01-14T08:00:00Z',
      read: true,
    },
    {
      id: 'a5',
      title: 'Info: Threat Feed Updated',
      severity: 'info',
      indicator: 'Threat feed sample',
      message: 'AlienVault OTX threat feed successfully synchronised. 1,247 new indicators ingested. [DEMONSTRATION DATA]',
      source: 'System',
      timestamp: '2025-01-14T06:00:00Z',
      read: true,
    },
    {
      id: 'a6',
      title: 'Critical: Malware Sample Correlated',
      severity: 'critical',
      indicator: 'a1b2c3d4…',
      message: 'File hash a1b2c3d4... has been matched to WellMess malware family with 82% confidence. The sample was found communicating with previously flagged C2 infrastructure. [DEMONSTRATION DATA]',
      source: 'Malware Analysis',
      timestamp: '2025-01-15T15:00:00Z',
      read: false,
    },
  ];
}

// ── Build a complete demo investigation ──
export function createDemoInvestigation(): Investigation {
  return {
    id: 'inv-001',
    query: 'suspicious-domain.test',
    type: 'domain',
    status: 'complete',
    startedAt: '2025-01-15T14:28:00Z',
    completedAt: '2025-01-15T14:36:00Z',
    risk: createDemoRisk(),
    findings: createDemoFindings(),
    domainIntel: createDemoDomainIntel(),
  };
}

// ── Additional demo investigations for history ──
export function createDemoHistory(): Investigation[] {
  return [
    createDemoInvestigation(),
    {
      id: 'inv-002',
      query: '198.51.100.23',
      type: 'ip',
      status: 'complete',
      startedAt: '2025-01-14T09:12:00Z',
      completedAt: '2025-01-14T09:18:00Z',
      risk: { score: 45, level: 'medium', confidence: 72, factors: [
        { name: 'Open Ports', impact: 20, description: 'Multiple non-standard ports open' },
        { name: 'Geo Anomaly', impact: 15, description: 'IP located in high-risk region' },
        { name: 'No Threat Intel', impact: 10, description: 'Not found in threat feeds' },
      ], explanation: 'Moderate risk due to open ports and geographic location. No direct threat intelligence matches. [DEMONSTRATION DATA]' },
      findings: [
        {
          id: 'f-ip1', title: 'Multiple Open Ports', severity: 'medium', category: 'Port Analysis',
          description: 'Several non-standard ports detected open. [DEMONSTRATION DATA]',
          evidence: [{ type: 'network', label: 'Ports', content: '22, 80, 443, 8080, 8443' }],
          timestamp: '2025-01-14T09:15:00Z', source: 'Port Scanner',
        },
      ],
    },
    {
      id: 'inv-003',
      query: 'clean-example.test',
      type: 'domain',
      status: 'complete',
      startedAt: '2025-01-13T16:00:00Z',
      completedAt: '2025-01-13T16:05:00Z',
      risk: { score: 12, level: 'low', confidence: 90, factors: [
        { name: 'Clean Reputation', impact: 0, description: 'No matches in threat intelligence' },
      ], explanation: 'Low risk. Domain has clean reputation across all sources. [DEMONSTRATION DATA]' },
      findings: [
        {
          id: 'f-c1', title: 'No Threats Detected', severity: 'info', category: 'Overall',
          description: 'All scans completed with no malicious indicators found. [DEMONSTRATION DATA]',
          evidence: [], timestamp: '2025-01-13T16:05:00Z', source: 'All Modules',
        },
      ],
    },
    {
      id: 'inv-004',
      query: 'e3b0c44298fc1c149afbf4c8996fb924',
      type: 'hash',
      status: 'complete',
      startedAt: '2025-01-12T11:20:00Z',
      completedAt: '2025-01-12T11:28:00Z',
      risk: { score: 92, level: 'critical', confidence: 95, factors: [
        { name: 'Known Malware', impact: 50, description: 'Matched to known ransomware family' },
        { name: 'Active C2', impact: 30, description: 'Communicates with active C2 infrastructure' },
        { name: 'Recent Activity', impact: 12, description: 'Sample observed in the wild within 7 days' },
      ], explanation: 'Critical risk. Hash matches known ransomware with active C2 communications. [DEMONSTRATION DATA]' },
      findings: [
        {
          id: 'f-h1', title: 'Known Ransomware Sample', severity: 'critical', category: 'Malware Analysis',
          description: 'File hash matches LockBit 3.0 ransomware variant. [DEMONSTRATION DATA]',
          evidence: [
            { type: 'file', label: 'AV Detection', content: '54/70 engines detected as malicious' },
            { type: 'network', label: 'C2 Communication', content: 'Beacons to 203.0.113.42 every 120s' },
          ],
          timestamp: '2025-01-12T11:25:00Z', source: 'Malware Analysis Module',
        },
      ],
    },
    {
      id: 'inv-005',
      query: 'https://login-verify-account.test/session',
      type: 'url',
      status: 'complete',
      startedAt: '2025-01-11T14:10:00Z',
      completedAt: '2025-01-11T14:15:00Z',
      risk: {
        score: 84,
        level: 'high',
        confidence: 88,
        factors: [
          { name: 'Credential Harvesting Form', impact: 40, description: 'Mimics legitimate corporate SSO login' },
          { name: 'Dynamic Redirect Chain', impact: 25, description: 'Contains 3 evasive redirect hops' },
          { name: 'Unregistered SSL Subject', impact: 19, description: 'TLS certificate issued by untrusted authority' },
        ],
        explanation: 'High risk credential phishing destination. Harvests authentication tokens and relays to external exfiltration endpoints. [DEMONSTRATION DATA]',
      },
      findings: [
        {
          id: 'f-u1',
          title: 'Active Phishing Landing Page',
          severity: 'high',
          category: 'URL Analysis',
          description: 'Web page contains obfuscated JavaScript designed to harvest credentials. [DEMONSTRATION DATA]',
          evidence: [
            { type: 'network', label: 'HTTP POST Target', content: 'Submits form data to 198.51.100.23/gate.php' },
            { type: 'log', label: 'Obfuscation Flag', content: 'Packed with eval(String.fromCharCode(...)) routine' },
          ],
          timestamp: '2025-01-11T14:12:00Z',
          source: 'DOM Inspector Module',
        },
      ],
    },
    {
      id: 'inv-006',
      query: 'phisher@covert-campaign.test',
      type: 'email',
      status: 'complete',
      startedAt: '2025-01-10T08:45:00Z',
      completedAt: '2025-01-10T08:52:00Z',
      risk: {
        score: 74,
        level: 'high',
        confidence: 80,
        factors: [
          { name: 'Spear-Phishing Sender', impact: 35, description: 'Associated with targeted BEC campaign lures' },
          { name: 'SPF/DKIM Alignment Failure', impact: 25, description: 'Header spoofing detected across mail relays' },
          { name: 'Domain Age < 10 Days', impact: 14, description: 'Sending domain recently registered' },
        ],
        explanation: 'High risk email indicator. Correlated with fraudulent invoice notifications and credential stealer payloads. [DEMONSTRATION DATA]',
      },
      findings: [
        {
          id: 'f-e1',
          title: 'Phishing Campaign Lure Sender',
          severity: 'high',
          category: 'Email Intelligence',
          description: 'Email identity distributed malicious macro-enabled documents to 14 corporate recipients. [DEMONSTRATION DATA]',
          evidence: [
            { type: 'log', label: 'Mail Server Headers', content: 'Originating IP: 192.0.2.1, SPF: Fail, DMARC: Reject' },
          ],
          timestamp: '2025-01-10T08:48:00Z',
          source: 'Email Security Gateway',
        },
      ],
    },
    {
      id: 'inv-007',
      query: 'apt_ghost_operator',
      type: 'username',
      status: 'complete',
      startedAt: '2025-01-09T18:20:00Z',
      completedAt: '2025-01-09T18:26:00Z',
      risk: {
        score: 66,
        level: 'medium',
        confidence: 75,
        factors: [
          { name: 'Dark Web Forum Presence', impact: 30, description: 'Handle observed advertising access brokers on underground forums' },
          { name: 'Tooling Repository Attribution', impact: 22, description: 'Associated with public GitHub repositories containing customized loaders' },
          { name: 'Infrastructure Overlap', impact: 14, description: 'Username used in WHOIS records of historical C2 domains' },
        ],
        explanation: 'Medium-high risk threat actor handle. Co-occurs across exploit broker forums and initial access broker discussions. [DEMONSTRATION DATA]',
      },
      findings: [
        {
          id: 'f-user1',
          title: 'Underground Forum Actor Handle',
          severity: 'medium',
          category: 'Actor Intelligence',
          description: 'Alias active across Russian-language cybercrime forums offering initial access and corporate VPN credentials. [DEMONSTRATION DATA]',
          evidence: [
            { type: 'log', label: 'Forum Profiling', content: 'Reputation score: 4.8/5 on Exploit[.]in; 12 successful escrow transactions' },
          ],
          timestamp: '2025-01-09T18:24:00Z',
          source: 'OSINT & Threat Actor Tracker',
        },
      ],
    },
  ];
}

// ── Dashboard stats from demo data ──
export function computeDashboardStats(investigations: Investigation[]): DashboardStats {
  const allFindings = investigations.flatMap(i => i.findings);
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  allFindings.forEach(f => { bySeverity[f.severity]++; });
  const scores = investigations.map(i => i.risk.score);
  return {
    totalInvestigations: investigations.length,
    activeScans: investigations.filter(i => i.status === 'scanning').length,
    criticalFindings: bySeverity.critical + bySeverity.high,
    avgRiskScore: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0,
    findingsBySeverity: bySeverity,
  };
}
