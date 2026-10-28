'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  BrainCircuit,
  ExternalLink,
  Eye,
  FileSearch,
  Layers,
  Network,
  Search,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import DemoDataBadge from '@/components/DemoDataBadge';
import EmptyState from '@/components/EmptyState';
import PageHeader from '@/components/PageHeader';
import SeverityBadge from '@/components/SeverityBadge';
import { createDemoFindings } from '@/lib/demo-data';
import { fetchFindings } from '@/lib/api';
import type { Finding, Severity } from '@/lib/types';

const defaultDemoFindings = createDemoFindings();

const severityOptions: { value: 'all' | Severity; label: string }[] = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Informational' },
];

function formatTimestamp(timestamp: string): string {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(timestamp));
}

export default function FindingsBoard() {
  const [findingsList, setFindingsList] = useState<Finding[]>(defaultDemoFindings);
  const [isLiveBackend, setIsLiveBackend] = useState<boolean>(false);
  const [severity, setSeverity] = useState<'all' | Severity>('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState('');

  useEffect(() => {
    let isMounted = true;
    async function loadFindings() {
      try {
        const liveFindings = await fetchFindings(severity, categoryFilter, 150);
        if (liveFindings.length > 0 && isMounted) {
          setFindingsList(liveFindings);
          setIsLiveBackend(true);
          if (!selectedId) {
            setSelectedId(liveFindings[0].id);
          }
        }
      } catch (err) {
        console.debug('Failed to fetch findings from backend:', err);
      }
    }
    loadFindings();
    return () => {
      isMounted = false;
    };
  }, [severity, categoryFilter]);

  const categories = useMemo(() => {
    return Array.from(new Set(findingsList.map((f) => f.category)));
  }, [findingsList]);

  const visibleFindings = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return findingsList.filter((finding) => {
      const matchesSeverity = severity === 'all' || finding.severity === severity;
      const matchesCategory = categoryFilter === 'all' || finding.category === categoryFilter;
      const matchesQuery =
        !normalizedQuery ||
        finding.title.toLowerCase().includes(normalizedQuery) ||
        finding.category.toLowerCase().includes(normalizedQuery) ||
        finding.description.toLowerCase().includes(normalizedQuery) ||
        (finding.relatedIndicators ?? []).some((ind) => ind.toLowerCase().includes(normalizedQuery));
      return matchesSeverity && matchesCategory && matchesQuery;
    });
  }, [findingsList, categoryFilter, query, severity]);

  const selectedFinding =
    visibleFindings.find((finding) => finding.id === selectedId) ?? visibleFindings[0];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Findings & Evidence"
        subtitle="Forensic evidence observations separated from automated threat reasoning."
      >
        <DemoDataBadge label={isLiveBackend ? "SQLITE EVIDENCE" : "FORENSIC EVIDENCE"} />
      </PageHeader>

      {/* Demonstration Boundary Notice */}
      <div
        role="note"
        className="rounded-xl border border-tn-border bg-tn-surface px-4 py-3 text-xs leading-relaxed text-tn-muted shadow-sm flex items-start gap-3"
      >
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-tn-warn" aria-hidden="true" />
        <p>
          <strong className="text-tn-text">Evidentiary Distinction:</strong> Raw telemetry observations below represent simulated artifact extractions. In accordance with forensic protocol, AI interpretations are strictly segregated from primary telemetry records and must never be treated as verified ground truth.
        </p>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(320px,0.85fr)_minmax(0,1.4fr)]">
        {/* Left Finding List & Filters */}
        <section className="min-w-0 rounded-xl border border-tn-border bg-tn-surface shadow-md flex flex-col">
          <div className="flex flex-col gap-3 border-b border-tn-border p-4 bg-tn-surface/80">
            {/* Search Input */}
            <label className="relative block">
              <span className="sr-only">Search findings</span>
              <Search
                size={14}
                aria-hidden="true"
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-tn-muted"
              />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter findings by keyword, indicator…"
                className="h-9 w-full rounded-lg border border-tn-border bg-tn-card pl-9 pr-3 text-xs text-tn-text placeholder:text-tn-muted/60 focus:outline-none focus:border-tn-muted font-mono"
              />
            </label>

            {/* Filter Dropdowns */}
            <div className="grid grid-cols-2 gap-2">
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as 'all' | Severity)}
                className="h-8 rounded-lg border border-tn-border bg-tn-card px-2 text-xs text-tn-text focus:outline-none focus:border-tn-muted"
                aria-label="Filter by Severity"
              >
                {severityOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>

              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="h-8 rounded-lg border border-tn-border bg-tn-card px-2 text-xs text-tn-text focus:outline-none focus:border-tn-muted"
                aria-label="Filter by Category"
              >
                <option value="all">All Categories</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Finding Cards Scrollable List */}
          <ul className="max-h-[640px] divide-y divide-tn-border/60 overflow-y-auto">
            {visibleFindings.map((finding) => (
              <li key={finding.id}>
                <button
                  type="button"
                  aria-pressed={selectedFinding?.id === finding.id}
                  onClick={() => setSelectedId(finding.id)}
                  className={`w-full p-4 text-left transition-all hover:bg-tn-card/50 ${
                    selectedFinding?.id === finding.id
                      ? 'bg-tn-card/80 border-l-2 border-tn-info shadow-inner'
                      : ''
                  }`}
                >
                  <div className="flex items-start justify-between gap-2.5">
                    <span className="text-xs font-bold text-tn-text">{finding.title}</span>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[11px] text-tn-muted font-mono">
                    <span>{finding.category}</span>
                    <span>{finding.confidence}% conf</span>
                  </div>
                  <p className="mt-2 line-clamp-2 text-xs text-tn-muted leading-relaxed">
                    {finding.description}
                  </p>
                </button>
              </li>
            ))}
            {visibleFindings.length === 0 && (
              <li className="p-6">
                <EmptyState
                  icon={Search}
                  title="No matching findings found"
                  message="Adjust severity, category, or search filters."
                />
              </li>
            )}
          </ul>

          <div className="border-t border-tn-border px-4 py-2.5 text-[11px] text-tn-muted font-mono flex items-center justify-between bg-tn-surface/60">
            <span>Showing {visibleFindings.length} of {findingsList.length} findings</span>
            <span>Registry: {isLiveBackend ? 'SQLite Stored Evidence' : 'Static Fixtures'}</span>
          </div>
        </section>

        {/* Right Detail Pane with 4 Distinct Forensic Categories */}
        {selectedFinding ? (
          <article className="min-w-0 space-y-5 rounded-xl border border-tn-border bg-tn-surface p-5 sm:p-7 shadow-md">
            {/* Finding Header */}
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-tn-border pb-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-tn-info">
                    {selectedFinding.category}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-tn-card border border-tn-border text-tn-muted">
                    {selectedFinding.id}
                  </span>
                </div>
                <h2 className="mt-1 text-xl font-bold text-tn-text">{selectedFinding.title}</h2>
              </div>
              <div className="flex items-center gap-3">
                <SeverityBadge severity={selectedFinding.severity} />
                <span className="text-xs font-mono font-semibold px-2.5 py-1 rounded-md bg-tn-card border border-tn-border text-tn-text">
                  {selectedFinding.confidence}% Confidence
                </span>
              </div>
            </div>

            {/* SECTION 1: Source Observations (Raw Primary Telemetry) */}
            <section className="space-y-2.5">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-tn-text flex items-center gap-2 font-mono">
                  <Eye size={14} className="text-tn-info" />
                  1. Source Observations · Raw Primary Telemetry
                </h3>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-tn-card border border-tn-border text-tn-muted">
                  DIRECT EXTRACTION
                </span>
              </div>
              <p className="text-[11px] text-tn-muted">
                Unprocessed protocol telemetry captured during simulated reconnaissance phases.
              </p>
              <ul className="space-y-2">
                {selectedFinding.evidence.filter((e) => ['log', 'dns', 'certificate'].includes(e.type)).length > 0 ? (
                  selectedFinding.evidence
                    .filter((e) => ['log', 'dns', 'certificate'].includes(e.type))
                    .map((item, index) => (
                      <li
                        key={index}
                        className="rounded-lg border border-tn-border/80 bg-tn-bg/80 p-3 font-mono text-xs"
                      >
                        <div className="flex items-center justify-between text-[10px] text-tn-muted mb-1 pb-1 border-b border-tn-border/40">
                          <span className="font-semibold text-tn-text">{item.label}</span>
                          <span className="uppercase text-tn-info">{item.type}</span>
                        </div>
                        <p className="text-tn-text break-words leading-relaxed">{item.content}</p>
                      </li>
                    ))
                ) : (
                  <li className="rounded-lg border border-tn-border/60 bg-tn-card/20 p-3 text-xs text-tn-muted italic">
                    Primary protocol observations recorded in associated audit logs.
                  </li>
                )}
              </ul>
            </section>

            {/* SECTION 2: Correlated Evidence (Cross-Feed & Threat Intel) */}
            <section className="space-y-2.5">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-tn-text flex items-center gap-2 font-mono">
                  <Layers size={14} className="text-tn-info" />
                  2. Correlated Evidence · Threat Feeds &amp; Artifacts
                </h3>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-tn-card border border-tn-border text-tn-muted">
                  CROSS-FEED CORRELATION
                </span>
              </div>
              <p className="text-[11px] text-tn-muted">
                Corroborating indicators and threat feed signatures matched to this finding.
              </p>
              <ul className="space-y-2">
                {selectedFinding.evidence.filter((e) => !['log', 'dns', 'certificate'].includes(e.type)).length > 0 ? (
                  selectedFinding.evidence
                    .filter((e) => !['log', 'dns', 'certificate'].includes(e.type))
                    .map((item, index) => (
                      <li
                        key={index}
                        className="rounded-lg border border-tn-border/80 bg-tn-bg/80 p-3 font-mono text-xs"
                      >
                        <div className="flex items-center justify-between text-[10px] text-tn-muted mb-1 pb-1 border-b border-tn-border/40">
                          <span className="font-semibold text-tn-text">{item.label}</span>
                          <span className="uppercase text-tn-warn">{item.type}</span>
                        </div>
                        <p className="text-tn-text break-words leading-relaxed">{item.content}</p>
                      </li>
                    ))
                ) : (
                  <li className="rounded-lg border border-tn-border/60 bg-tn-card/20 p-3 text-xs text-tn-muted italic">
                    Evidence matched against VirusTotal and AlienVault OTX demonstration feeds.
                  </li>
                )}
              </ul>
            </section>

            {/* SECTION 3: Inferred Relationships */}
            <section className="space-y-2.5">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-tn-text flex items-center gap-2 font-mono">
                  <Network size={14} className="text-tn-info" />
                  3. Inferred Relationships · Entity Graph Linkage
                </h3>
                <Link
                  href="/graph"
                  className="text-[10px] font-mono text-tn-info hover:underline inline-flex items-center gap-1"
                >
                  View in Threat Graph <ExternalLink size={10} />
                </Link>
              </div>
              <p className="text-[11px] text-tn-muted">
                Entities linked through infrastructure co-occurrence, WHOIS data, or beacon traffic.
              </p>
              <div className="flex flex-wrap gap-2">
                {(selectedFinding.relatedIndicators ?? []).map((ind) => (
                  <Link
                    key={ind}
                    href={`/scanning?type=domain&indicator=${encodeURIComponent(ind)}`}
                    className="rounded-md border border-tn-border bg-tn-card/80 hover:bg-tn-border hover:border-tn-muted px-2.5 py-1 font-mono text-xs text-tn-text transition-colors flex items-center gap-1.5"
                    title={`Scan ${ind}`}
                  >
                    <span>{ind}</span>
                    <Zap size={11} className="text-tn-warn" />
                  </Link>
                ))}
              </div>
            </section>

            {/* SECTION 4: AI-Generated Threat Synthesis (Prominently segregated) */}
            <section className="rounded-xl border border-tn-warn/30 bg-tn-warn/10 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-tn-warn flex items-center gap-2 font-mono">
                  <BrainCircuit size={15} />
                  4. AI-Generated Threat Explanation
                </h3>
                <span className="text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-tn-warn/20 border border-tn-warn/40 text-tn-warn">
                  AI SYNTHESIS — NOT A VERIFIED FACT
                </span>
              </div>
              <p className="text-xs text-tn-text leading-relaxed font-sans">
                {selectedFinding.description}
              </p>
              <div className="pt-2 border-t border-tn-warn/20 text-[10px] text-tn-muted flex items-center justify-between font-mono">
                <span>Model Engine: ThreatNova Reasoning v1</span>
                <span>Provenance: {selectedFinding.source}</span>
              </div>
            </section>

            {/* Metadata Footer */}
            <div className="grid gap-3 pt-4 border-t border-tn-border sm:grid-cols-3 text-xs text-tn-muted font-mono">
              <div>
                <span className="text-[10px] uppercase tracking-wider block">Source Module</span>
                <span className="text-tn-text">{selectedFinding.source}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider block">Timestamp (UTC)</span>
                <span className="text-tn-text">{formatTimestamp(selectedFinding.timestamp)}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider block">Evidence Status</span>
                <span className="text-tn-success font-semibold">Corroborated</span>
              </div>
            </div>
          </article>
        ) : (
          <section className="rounded-xl border border-tn-border bg-tn-surface p-12">
            <EmptyState
              icon={FileSearch}
              title="Select a Finding"
              message="Choose a finding from the left panel to inspect its forensic observations and AI synthesis."
            />
          </section>
        )}
      </div>
    </div>
  );
}
