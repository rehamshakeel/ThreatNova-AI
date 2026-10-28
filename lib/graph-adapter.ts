// lib/graph-adapter.ts
// Centralized adapter mapping real investigation evidence into Root Tree data structures.

import type { Finding, Investigation, Severity } from './types';

export interface TreeNodeItem {
  id: string;
  name: string;
  nodeType: 'root' | 'category' | 'finding';
  severity?: Severity;
  category?: string;
  findingCount?: number;
  findingRef?: Finding;
  investigationRef?: Investigation;
  children?: TreeNodeItem[];
  emptyReason?: string;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function getHighestSeverity(severities: Severity[]): Severity {
  if (!severities.length) return 'info';
  let highest: Severity = severities[0];
  for (const s of severities) {
    if ((severityRank[s] || 0) > (severityRank[highest] || 0)) {
      highest = s;
    }
  }
  return highest;
}

/**
 * Transforms an Investigation into a hierarchical Root Tree:
 * Root: Target Indicator
 * Branches: Telemetry Categories (Findings, DNS, WHOIS, TLS, Routing, Risk Signals)
 * Leaves: Real empirical evidence records, extracted indicators, and source metadata
 */
export function adaptInvestigationToTree(
  inv: Investigation | null | undefined,
  severityFilter: string = 'all'
): { root: TreeNodeItem | null; totalEvidenceCount: number; emptyReason?: string } {
  if (!inv) {
    return {
      root: null,
      totalEvidenceCount: 0,
      emptyReason: 'No investigation selected.',
    };
  }

  const categoryMap = new Map<string, TreeNodeItem[]>();

  // Helper to add a leaf node under a category branch
  function addLeaf(
    category: string,
    leaf: {
      id: string;
      name: string;
      severity: Severity;
      findingRef?: Finding;
    }
  ) {
    if (severityFilter !== 'all' && leaf.severity !== severityFilter) {
      return;
    }
    if (!categoryMap.has(category)) {
      categoryMap.set(category, []);
    }
    categoryMap.get(category)!.push({
      id: leaf.id,
      name: leaf.name,
      nodeType: 'finding',
      severity: leaf.severity,
      category,
      findingRef: leaf.findingRef,
    });
  }

  // 1. Empirical Findings
  if (Array.isArray(inv.findings) && inv.findings.length > 0) {
    for (const f of inv.findings) {
      const cat = f.category || 'Threat Intelligence';
      addLeaf(cat, {
        id: `finding-${f.id}`,
        name: f.title,
        severity: f.severity,
        findingRef: f,
      });
    }
  }

  // 2. Domain & Network Intelligence Enrichment
  const dIntel = inv.domainIntel;
  if (dIntel) {
    // DNS Records
    if (Array.isArray(dIntel.dns) && dIntel.dns.length > 0) {
      for (const rec of dIntel.dns.slice(0, 5)) {
        addLeaf('DNS Records', {
          id: `dns-${rec.type}-${rec.value}`,
          name: `${rec.type}: ${rec.value}`,
          severity: 'info',
        });
      }
    }

    // WHOIS Registration Data
    if (dIntel.whois) {
      if (dIntel.whois.registrar) {
        addLeaf('WHOIS Registration', {
          id: `whois-reg-${inv.id}`,
          name: `Registrar: ${dIntel.whois.registrar}`,
          severity: 'info',
        });
      }
      if (dIntel.whois.createdDate) {
        addLeaf('WHOIS Registration', {
          id: `whois-date-${inv.id}`,
          name: `Created: ${dIntel.whois.createdDate}`,
          severity: 'info',
        });
      }
    }

    // TLS Certificate
    if (dIntel.ssl) {
      if (dIntel.ssl.subject) {
        addLeaf('TLS Certificate', {
          id: `ssl-subj-${inv.id}`,
          name: `Subject: ${dIntel.ssl.subject}`,
          severity: dIntel.ssl.isValid ? 'low' : 'high',
        });
      }
      if (dIntel.ssl.issuer) {
        addLeaf('TLS Certificate', {
          id: `ssl-issuer-${inv.id}`,
          name: `Issuer: ${dIntel.ssl.issuer}`,
          severity: 'info',
        });
      }
    }

    // IP Geolocation & ASN
    const geo = inv.geolocation || dIntel.geo;
    if (geo) {
      if (geo.resolved_ip || geo.ip) {
        addLeaf('Network & Routing', {
          id: `net-ip-${inv.id}`,
          name: `IP: ${geo.resolved_ip || geo.ip}`,
          severity: 'info',
        });
      }
      if (geo.asn) {
        addLeaf('Network & Routing', {
          id: `net-asn-${inv.id}`,
          name: `ASN: ${geo.asn}`,
          severity: 'info',
        });
      }
      if (geo.city || geo.country) {
        const loc = [geo.city, geo.country].filter(Boolean).join(', ');
        addLeaf('Network & Routing', {
          id: `net-loc-${inv.id}`,
          name: `Location: ${loc}`,
          severity: 'info',
        });
      }
      if (geo.is_cdn_edge) {
        addLeaf('Network & Routing', {
          id: `net-edge-${inv.id}`,
          name: `CDN Edge: ${geo.note || 'Closest Gateway'}`,
          severity: 'info',
        });
      }
    }
  }

  // 3. Correlated Risk Factors
  if (Array.isArray(inv.risk?.factors) && inv.risk.factors.length > 0) {
    for (const rf of inv.risk.factors) {
      const sev: Severity =
        rf.impact >= 35 ? 'critical' : rf.impact >= 20 ? 'high' : rf.impact >= 10 ? 'medium' : 'low';
      addLeaf('Risk Signals', {
        id: `rf-${rf.name}-${inv.id}`,
        name: `${rf.name} (+${rf.impact})`,
        severity: sev,
      });
    }
  }

  // Build Root Node
  const rootNode: TreeNodeItem = {
    id: `root-${inv.id}`,
    name: inv.query,
    nodeType: 'root',
    severity: inv.risk?.level ?? 'info',
    investigationRef: inv,
    children: [],
  };

  let totalEvidenceCount = 0;

  categoryMap.forEach((leaves, catName) => {
    if (leaves.length === 0) return;
    totalEvidenceCount += leaves.length;
    const branchSev = getHighestSeverity(leaves.map((l) => l.severity || 'info'));
    rootNode.children!.push({
      id: `cat-${catName}`,
      name: catName,
      nodeType: 'category',
      severity: branchSev,
      findingCount: leaves.length,
      children: leaves,
    });
  });

  const emptyReason =
    totalEvidenceCount === 0
      ? `No forensic findings or telemetry enrichment records are available for "${inv.query}".`
      : undefined;

  return {
    root: rootNode,
    totalEvidenceCount,
    emptyReason,
  };
}
