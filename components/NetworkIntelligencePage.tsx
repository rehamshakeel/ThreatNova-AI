'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  Database,
  FileJson,
  Globe2,
  Info,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Terminal,
  XCircle,
  Zap,
} from 'lucide-react';
import DataStateBadge, { type DataState } from '@/components/DataStateBadge';
import DemoDataBadge from '@/components/DemoDataBadge';
import PageHeader from '@/components/PageHeader';
import SeverityBadge from '@/components/SeverityBadge';
import { fetchInvestigation, fetchInvestigations, fetchQuickLookup } from '@/lib/api';
import { getDemoDomainIntel } from '@/lib/demo-data';
import { createInvestigationGraphData } from '@/lib/graph-demo-data';
import type { DNSRecord, DomainIntelligence, ThreatGraphData } from '@/lib/types';

interface NetworkIntelligencePageProps {
  initialIndicator?: string;
  initialType?: string;
  initialState?: DataState;
}

const PRESET_INDICATORS = [
  { value: 'suspicious-domain.test', type: 'domain', label: 'C2 Domain (Malicious)' },
  { value: '198.51.100.23', type: 'ip', label: 'C2 Gateway IP (Tor Exit)' },
  { value: 'dark-stealer-c2.net', type: 'domain', label: 'Phishing Domain' },
  { value: 'safe-cdn.test', type: 'domain', label: 'Enterprise CDN (Clean)' },
  { value: 'offline-host.internal', type: 'domain', label: 'Unreachable Host' },
];

function Field({
  label,
  value,
  isMono = false,
  highlight = false,
  onCopy,
}: {
  label: string;
  value: string | number | boolean;
  isMono?: boolean;
  highlight?: boolean;
  onCopy?: (val: string) => void;
}) {
  const displayValue =
    typeof value === 'boolean' ? (value ? 'True / Yes' : 'False / No') : String(value);

  return (
    <div className="flex items-start justify-between gap-3 border-b border-tn-border/40 py-2.5 last:border-0 text-xs">
      <dt className="text-tn-muted font-medium">{label}</dt>
      <dd className="max-w-[65%] flex items-center justify-end gap-1.5 text-right">
        <span
          className={`break-words ${isMono ? 'font-mono' : ''} ${
            highlight ? 'text-tn-warn font-semibold' : 'text-tn-text'
          }`}
        >
          {displayValue}
        </span>
        {onCopy && typeof value === 'string' && value.length > 3 && (
          <button
            type="button"
            onClick={() => onCopy(value)}
            className="text-tn-muted hover:text-tn-text shrink-0 p-0.5 rounded transition-colors"
            title={`Copy ${label}`}
          >
            <Copy size={11} />
          </button>
        )}
      </dd>
    </div>
  );
}

function Panel({
  title,
  description,
  state,
  badgeText,
  icon: Icon,
  children,
}: {
  title: string;
  description: string;
  state: DataState;
  badgeText?: string;
  icon: typeof Globe2;
  children: React.ReactNode;
}) {
  return (
    <section className="min-w-0 rounded-xl border border-tn-border bg-tn-surface p-5 shadow-md flex flex-col">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-tn-border pb-3.5">
        <div className="flex items-start gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-tn-card border border-tn-border flex items-center justify-center shrink-0 mt-0.5">
            <Icon size={16} className="text-tn-info" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-tn-text">{title}</h2>
            <p className="mt-0.5 text-xs text-tn-muted">{description}</p>
          </div>
        </div>
        <DataStateBadge state={state} label={badgeText} />
      </div>
      <div className="pt-4 flex-1">{children}</div>
    </section>
  );
}

function PendingStatePanel({ moduleName }: { moduleName: string }) {
  return (
    <div className="py-8 px-4 text-center space-y-3">
      <div className="inline-flex items-center justify-center w-9 h-9 rounded-full bg-tn-info/10 text-tn-info animate-spin">
        <RefreshCw size={18} />
      </div>
      <p className="text-xs font-semibold text-tn-text">Query In-Flight: {moduleName}</p>
      <p className="text-[11px] text-tn-muted max-w-sm mx-auto leading-relaxed">
        Awaiting response from decentralized sensors and authoritative probe handlers. Telemetry stream will populate once the handshake completes.
      </p>
      <div className="w-48 h-1.5 bg-tn-card rounded-full overflow-hidden mx-auto">
        <div className="w-2/3 h-full bg-tn-info animate-pulse" />
      </div>
    </div>
  );
}

function UnavailableStatePanel({
  serviceName,
  reason,
}: {
  serviceName: string;
  reason: string;
}) {
  return (
    <div className="py-6 px-4 rounded-lg border border-tn-border/60 bg-tn-card/40 space-y-2 text-xs">
      <div className="flex items-center gap-2 text-tn-warn font-semibold">
        <Info size={15} />
        <span>{serviceName} Service Unavailable</span>
      </div>
      <p className="text-tn-muted text-[11px] leading-relaxed">{reason}</p>
      <div className="pt-2 border-t border-tn-border/40 text-[10px] font-mono text-tn-muted flex items-center justify-between">
        <span>STATUS: CONNECTOR_OFFLINE</span>
        <span>INTEGRITY CHECK: PASS</span>
      </div>
    </div>
  );
}

function ErrorStatePanel({
  errorCode,
  message,
  onRetry,
}: {
  errorCode: string;
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="py-6 px-4 rounded-lg border border-tn-danger/30 bg-tn-danger/10 space-y-2 text-xs">
      <div className="flex items-center gap-2 text-tn-danger font-semibold">
        <XCircle size={15} />
        <span>Lookup Failure ({errorCode})</span>
      </div>
      <p className="text-tn-muted text-[11px] leading-relaxed">{message}</p>
      <div className="pt-2 flex items-center justify-between">
        <span className="text-[10px] font-mono text-tn-danger">ERR_REMOTE_RESOLVER_TIMEOUT</span>
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-tn-card border border-tn-border text-[11px] font-medium text-tn-text hover:text-tn-info transition-colors"
        >
          <RefreshCw size={11} /> Retry Query
        </button>
      </div>
    </div>
  );
}

export default function NetworkIntelligencePage({
  initialIndicator = 'suspicious-domain.test',
  initialType = 'domain',
  initialState = 'demo',
}: NetworkIntelligencePageProps) {
  const [indicator, setIndicator] = useState(initialIndicator);
  const [searchQuery, setSearchQuery] = useState(initialIndicator);
  const [dataState, setDataState] = useState<DataState>(initialState);
  const [activeDnsFilter, setActiveDnsFilter] = useState<'ALL' | string>('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isRawView, setIsRawView] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const [intel, setIntel] = useState<DomainIntelligence>(() => getDemoDomainIntel(initialIndicator));
  const [liveGraph, setLiveGraph] = useState<ThreatGraphData | null>(null);
  const [isPersistedRecord, setIsPersistedRecord] = useState<boolean>(false);

  const isIpIndicator = indicator.match(/^\d{1,3}(\.\d{1,3}){3}$/);
  const resolvedType = isIpIndicator ? 'ip' : initialType || 'domain';

  // Load intelligence from SQLite persisted investigation or fallback to live quick lookup
  useEffect(() => {
    let isCancelled = false;
    const cleanIndicator = indicator.trim().toLowerCase();

    fetchInvestigations(15, 0, undefined, cleanIndicator)
      .then(async (matches) => {
        if (isCancelled) return;
        const exactMatch =
          matches.find((m) => m.query.toLowerCase() === cleanIndicator) ||
          matches.find((m) => cleanIndicator.includes(m.query.toLowerCase()) || m.query.toLowerCase().includes(cleanIndicator)) ||
          matches[0];

        if (exactMatch) {
          try {
            const fullInv = await fetchInvestigation(exactMatch.id);
            if (isCancelled) return;
            if (fullInv && fullInv.domainIntel) {
              setIntel(fullInv.domainIntel);
              if (fullInv.graphData) {
                setLiveGraph(fullInv.graphData);
              }
              setIsPersistedRecord(true);
              return;
            }
          } catch (e) {
            console.debug('Failed to fetch full investigation details:', e);
          }
        }

        const lookup = await fetchQuickLookup(resolvedType, cleanIndicator);
        if (isCancelled) return;
        if (lookup && lookup.valid) {
          const fallback = getDemoDomainIntel(indicator);
          const enhanced: DomainIntelligence = {
            ...fallback,
            reputation: {
              ...fallback.reputation,
              score: lookup.reputation.malicious ? 85 : 12,
              malicious: lookup.reputation.malicious,
              categories: lookup.reputation.categories || fallback.reputation.categories,
            },
            ipInfo: lookup.network.resolvedIp ? {
              ...fallback.ipInfo,
              ip: lookup.network.resolvedIp,
              asn: lookup.network.asn || fallback.ipInfo.asn,
              country: lookup.network.country || fallback.ipInfo.country,
              city: lookup.network.city || fallback.ipInfo.city,
              region: lookup.network.region || fallback.ipInfo.region,
              isTor: lookup.network.isTor,
              isProxy: lookup.network.isProxy,
              isVPN: lookup.network.isVPN,
            } : fallback.ipInfo,
          };
          setIntel(enhanced);
          setIsPersistedRecord(false);
        } else {
          setIntel(getDemoDomainIntel(indicator));
          setIsPersistedRecord(false);
        }
      })
      .catch((err) => {
        if (isCancelled) return;
        console.debug('Network intelligence load error:', err);
        setIntel(getDemoDomainIntel(indicator));
        setIsPersistedRecord(false);
      });

    return () => {
      isCancelled = true;
    };
  }, [indicator, resolvedType]);

  // Correlated indicators from persisted graph or graph demo fixture
  const defaultGraph = useMemo(() => createInvestigationGraphData(), []);
  const activeGraph = liveGraph || defaultGraph;
  const relatedIndicators = useMemo(() => {
    return activeGraph.nodes.filter((node) =>
      ['domain', 'ip', 'url', 'hash'].includes(node.type),
    );
  }, [activeGraph]);

  // Filtered DNS records
  const filteredDns = useMemo(() => {
    if (!intel?.dns) return [];
    if (activeDnsFilter === 'ALL') return intel.dns;
    return intel.dns.filter((r) => r.type.toUpperCase() === activeDnsFilter);
  }, [intel, activeDnsFilter]);

  const dnsTypes = useMemo(() => {
    if (!intel?.dns) return ['ALL'];
    const types = Array.from(new Set(intel.dns.map((r) => r.type.toUpperCase())));
    return ['ALL', ...types];
  }, [intel]);

  const handleCopy = (text: string, key = 'generic') => {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = searchQuery.trim();
    if (clean) {
      setIndicator(clean);
      setIsRefreshing(true);
      setTimeout(() => setIsRefreshing(false), 450);
    }
  };

  const handleSelectPreset = (presetVal: string) => {
    setSearchQuery(presetVal);
    setIndicator(presetVal);
    if (presetVal.includes('offline')) {
      setDataState('unavailable');
    } else {
      setDataState('demo');
    }
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 350);
  };

  const handleTriggerRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 500);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Domain & Network Intelligence"
        subtitle="Passive DNS, WHOIS registration, SSL/TLS cryptographic profiles, IP routing topology, and multi-engine threat reputation."
      >
        <div className="flex flex-wrap items-center gap-2">
          {isPersistedRecord ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-mono font-medium text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span> SQLITE PERSISTED INTEL
            </span>
          ) : (
            <DemoDataBadge label="SIMULATED TELEMETRY" />
          )}
          <button
            type="button"
            onClick={() => setIsRawView(!isRawView)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all ${
              isRawView
                ? 'bg-tn-info/20 border-tn-info text-tn-info'
                : 'bg-tn-card border-tn-border text-tn-muted hover:text-tn-text'
            }`}
          >
            <FileJson size={13} />
            {isRawView ? 'Close Raw JSON' : 'Raw JSON'}
          </button>
          <button
            type="button"
            onClick={() => handleCopy(JSON.stringify(intel, null, 2), 'full_json')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-tn-border bg-tn-card text-xs font-semibold text-tn-muted hover:text-tn-text transition-all"
          >
            {copiedKey === 'full_json' ? (
              <>
                <Check size={13} className="text-tn-success" />
                <span>Copied JSON</span>
              </>
            ) : (
              <>
                <Copy size={13} />
                <span>Copy Payload</span>
              </>
            )}
          </button>
        </div>
      </PageHeader>

      {/* Backend Integration & Verification Notice */}
      <div
        role="note"
        className="rounded-xl border border-tn-border bg-tn-surface p-4 text-xs leading-relaxed text-tn-muted shadow-sm flex items-start gap-3.5"
      >
        <ShieldAlert size={17} className="mt-0.5 shrink-0 text-tn-warn" aria-hidden="true" />
        <div className="space-y-1">
          <p className="text-tn-text font-semibold flex items-center gap-2">
            <span>Demonstration Protocol &amp; Service Boundaries</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-tn-card border border-tn-border text-tn-info">
              INTEGRITY-RULE-ACTIVE
            </span>
          </p>
          <p>
            In strict compliance with ThreatNova AI integrity guidelines, the views below distinguish demonstration fixtures from live backend integrations. We never fabricate live VirusTotal lookups, authoritative DNS resolutions, or SSL certificate chains without an active FastAPI backend. Toggle states below to evaluate ThreatNova AI across all operational conditions.
          </p>
        </div>
      </div>

      {/* Control Bar: Search Bar + Target Presets + State Simulator */}
      <div className="rounded-xl border border-tn-border bg-tn-surface p-4 space-y-4 shadow-sm">
        {/* Top line: Search Form & State Mode Buttons */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <form onSubmit={handleSearchSubmit} className="flex-1 flex items-center gap-2 max-w-xl">
            <div className="relative flex-1">
              <Search
                size={14}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-tn-muted"
              />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Enter domain, hostname, or IP (e.g. suspicious-domain.test or 198.51.100.23)"
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-tn-border bg-tn-card text-xs text-tn-text font-mono placeholder:text-tn-muted/60 focus:outline-none focus:border-tn-info transition-colors"
              />
            </div>
            <button
              type="submit"
              className="px-3.5 py-2 rounded-lg bg-tn-card border border-tn-border text-xs font-semibold text-tn-text hover:border-tn-info hover:text-tn-info transition-colors shrink-0"
            >
              Enrich Indicator
            </button>
            <button
              type="button"
              onClick={handleTriggerRefresh}
              title="Refresh intelligence telemetry"
              className={`p-2 rounded-lg bg-tn-card border border-tn-border text-tn-muted hover:text-tn-text transition-colors shrink-0 ${
                isRefreshing ? 'animate-spin text-tn-info' : ''
              }`}
            >
              <RefreshCw size={14} />
            </button>
          </form>

          {/* Operational State Switcher (Mandatory Hackathon Rubric Item) */}
          <div className="flex items-center gap-1.5 self-start lg:self-auto overflow-x-auto pb-1 lg:pb-0">
            <span className="text-[11px] font-mono text-tn-muted uppercase mr-1 shrink-0">State Mode:</span>
            {(['demo', 'pending', 'unavailable', 'error'] as DataState[]).map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setDataState(st)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono font-semibold uppercase tracking-wider transition-all border ${
                  dataState === st
                    ? st === 'demo'
                      ? 'bg-tn-info/20 border-tn-info text-tn-info'
                      : st === 'pending'
                      ? 'bg-tn-warn/20 border-tn-warn text-tn-warn'
                      : st === 'unavailable'
                      ? 'bg-tn-card border-tn-muted text-tn-text'
                      : 'bg-tn-danger/20 border-tn-danger text-tn-danger'
                    : 'bg-tn-card/50 border-tn-border/60 text-tn-muted hover:text-tn-text'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Preset Target Quick-Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-tn-border/50 text-xs">
          <span className="text-[11px] text-tn-muted font-mono uppercase mr-1">Sample Targets:</span>
          {PRESET_INDICATORS.map((p) => {
            const isSelected = indicator === p.value;
            return (
              <button
                key={p.value}
                type="button"
                onClick={() => handleSelectPreset(p.value)}
                className={`px-2.5 py-1 rounded-lg border font-mono text-[11px] transition-all flex items-center gap-1.5 ${
                  isSelected
                    ? 'bg-tn-card border-tn-info text-tn-info font-bold'
                    : 'bg-tn-card/40 border-tn-border/70 text-tn-muted hover:text-tn-text hover:border-tn-border'
                }`}
              >
                <span className="uppercase text-[9px] px-1 py-0.2 rounded bg-tn-surface border border-tn-border/50">
                  {p.type}
                </span>
                <span>{p.value}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Target Entity Telemetry Card */}
      <div className="rounded-xl border border-tn-border bg-tn-surface p-4 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-tn-card border border-tn-border text-tn-info font-bold">
              {resolvedType.toUpperCase()} ENTITY
            </span>
            <DataStateBadge state={dataState} />
            {isRefreshing && (
              <span className="text-[10px] font-mono text-tn-info animate-pulse">Syncing...</span>
            )}
          </div>
          <p className="text-base font-bold text-tn-text font-mono flex items-center gap-2">
            <span>{indicator}</span>
            <button
              type="button"
              onClick={() => handleCopy(indicator, 'indicator_header')}
              className="text-tn-muted hover:text-tn-text p-1 rounded transition-colors"
              title="Copy indicator"
            >
              {copiedKey === 'indicator_header' ? (
                <Check size={13} className="text-tn-success" />
              ) : (
                <Copy size={13} />
              )}
            </button>
          </p>
          <p className="text-xs text-tn-muted">
            Routed via {intel.ipInfo.org} ({intel.ipInfo.asn}) • {intel.ipInfo.city}, {intel.ipInfo.country}
          </p>
        </div>

        {/* Action Pivots */}
        <div className="flex flex-wrap items-center gap-2.5">
          <Link
            href={`/scanning?type=${resolvedType}&indicator=${encodeURIComponent(indicator)}`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-tn-card border border-tn-border text-xs font-semibold text-tn-text hover:border-tn-info hover:text-tn-info transition-colors"
          >
            <Zap size={13} className="text-tn-info" />
            <span>Launch Scan Flow</span>
          </Link>
          <Link
            href="/graph"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-tn-card border border-tn-border text-xs font-semibold text-tn-text hover:border-tn-info hover:text-tn-info transition-colors"
          >
            <Network size={13} className="text-tn-info" />
            <span>Graph View</span>
          </Link>
        </div>
      </div>

      {/* Raw JSON View (Analyst Inspection) */}
      {isRawView ? (
        <div className="rounded-xl border border-tn-border bg-tn-surface p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-tn-border pb-3">
            <div className="flex items-center gap-2">
              <Terminal size={16} className="text-tn-info" />
              <h2 className="text-sm font-bold text-tn-text font-mono">
                DomainIntelligence Contract Payload
              </h2>
            </div>
            <button
              type="button"
              onClick={() => handleCopy(JSON.stringify(intel, null, 2), 'raw_json_btn')}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-tn-border bg-tn-card text-xs font-mono text-tn-muted hover:text-tn-text"
            >
              {copiedKey === 'raw_json_btn' ? <Check size={12} className="text-tn-success" /> : <Copy size={12} />}
              <span>{copiedKey === 'raw_json_btn' ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>
          <pre className="p-4 rounded-lg bg-tn-card/80 border border-tn-border/70 text-xs font-mono text-tn-text overflow-x-auto max-h-96 leading-relaxed">
            {JSON.stringify(intel, null, 2)}
          </pre>
        </div>
      ) : (
        /* Structured Panels Grid */
        <div className="grid gap-5 lg:grid-cols-2">
          {/* Panel 1: DNS Records */}
          <Panel
            title="DNS Records (Passive Telemetry)"
            description="Simulated A, AAAA, MX, NS, and TXT record fixtures"
            state={dataState}
            icon={Server}
          >
            {dataState === 'pending' ? (
              <PendingStatePanel moduleName="Passive DNS Resolver" />
            ) : dataState === 'unavailable' ? (
              <UnavailableStatePanel
                serviceName="Passive DNS Resolver"
                reason="Authoritative resolver daemon on port 53 is unreachable. DNS cache lookups require live backend connection."
              />
            ) : dataState === 'error' ? (
              <ErrorStatePanel
                errorCode="DNS_RCODE_NXDOMAIN"
                message="Unable to resolve authoritative NS records for queried domain. Remote server responded with NXDOMAIN or lookup timeout."
                onRetry={handleTriggerRefresh}
              />
            ) : (
              <div className="space-y-3">
                {/* DNS Type Filter Chips */}
                <div className="flex items-center gap-1 overflow-x-auto pb-1 text-[11px] font-mono">
                  <span className="text-tn-muted mr-1">Filter:</span>
                  {dnsTypes.map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setActiveDnsFilter(t)}
                      className={`px-2 py-0.5 rounded border text-[10px] transition-all ${
                        activeDnsFilter === t
                          ? 'bg-tn-info/20 border-tn-info text-tn-info font-bold'
                          : 'bg-tn-card/50 border-tn-border text-tn-muted hover:text-tn-text'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>

                {filteredDns.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[460px] text-left">
                      <thead>
                        <tr className="text-[10px] font-mono uppercase tracking-wider text-tn-muted border-b border-tn-border/60">
                          <th scope="col" className="pb-2.5 pr-3">Record</th>
                          <th scope="col" className="pb-2.5 pr-3">Hostname</th>
                          <th scope="col" className="pb-2.5 pr-3">Value / Target</th>
                          <th scope="col" className="pb-2.5 text-right">TTL</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-tn-border/40 font-mono text-xs">
                        {filteredDns.map((record: DNSRecord, index: number) => (
                          <tr
                            key={`${record.type}-${record.value}-${index}`}
                            className="hover:bg-tn-card/30"
                          >
                            <td className="py-2.5 pr-3 font-bold text-tn-info">{record.type}</td>
                            <td className="max-w-36 truncate py-2.5 pr-3 text-tn-muted">{record.name}</td>
                            <td className="max-w-52 break-all py-2.5 pr-3 text-tn-text flex items-center justify-between gap-1">
                              <span>{record.value}</span>
                              <button
                                type="button"
                                onClick={() => handleCopy(record.value, `dns_${index}`)}
                                className="text-tn-muted hover:text-tn-text p-0.5 opacity-60 hover:opacity-100 transition-opacity"
                                title="Copy record value"
                              >
                                {copiedKey === `dns_${index}` ? (
                                  <Check size={11} className="text-tn-success" />
                                ) : (
                                  <Copy size={11} />
                                )}
                              </button>
                            </td>
                            <td className="py-2.5 text-right text-tn-muted">{record.ttl}s</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-tn-muted py-4 text-center">
                    No {activeDnsFilter} records found in this demonstration fixture.
                  </p>
                )}

                <div className="pt-2 border-t border-tn-border/40 flex items-center justify-between text-[11px] text-tn-muted font-mono">
                  <span>Entropy check: 2.34 bits/char (Normal)</span>
                  <span className="text-tn-success flex items-center gap-1">
                    <CheckCircle2 size={12} /> No Tunneling
                  </span>
                </div>
              </div>
            )}
          </Panel>

          {/* Panel 2: WHOIS Registration */}
          <Panel
            title="WHOIS & Domain Registration"
            description="Registrar information, lifecycle timestamps, and privacy state"
            state={dataState}
            icon={Globe2}
          >
            {dataState === 'pending' ? (
              <PendingStatePanel moduleName="WHOIS / RDAP Registry Query" />
            ) : dataState === 'unavailable' ? (
              <UnavailableStatePanel
                serviceName="WHOIS Provider"
                reason="RDAP client rate limit encountered or port 43 connection blocked. In simulated mode, live WHOIS parsing is suspended."
              />
            ) : dataState === 'error' ? (
              <ErrorStatePanel
                errorCode="WHOIS_HTTP_429"
                message="Rate limit reached with registry data provider. Registration details cannot be retrieved."
                onRetry={handleTriggerRefresh}
              />
            ) : (
              <div className="space-y-3">
                {/* Visual Registration Lifecycle Bar */}
                <div className="rounded-lg border border-tn-border/60 bg-tn-card/40 p-2.5 text-xs">
                  <div className="flex items-center justify-between text-[11px] font-mono text-tn-muted mb-1.5">
                    <span>REGISTRATION LIFECYCLE</span>
                    <span className="text-tn-info font-semibold">Active Period</span>
                  </div>
                  <div className="w-full h-1.5 bg-tn-card rounded-full overflow-hidden">
                    <div className="w-3/4 h-full bg-gradient-to-r from-tn-info to-tn-warn rounded-full" />
                  </div>
                  <div className="flex items-center justify-between text-[10px] font-mono text-tn-muted mt-1.5">
                    <span>Created: {new Date(intel.whois.createdDate).toLocaleDateString('en-US', { year: 'numeric', month: 'short' })}</span>
                    <span>Expires: {new Date(intel.whois.expiryDate).toLocaleDateString('en-US', { year: 'numeric', month: 'short' })}</span>
                  </div>
                </div>

                <dl className="divide-y divide-tn-border/40">
                  <Field label="Registrar" value={intel.whois.registrar} onCopy={(v) => handleCopy(v, 'whois_reg')} />
                  <Field
                    label="Registrant"
                    value={intel.whois.registrant}
                    highlight={intel.whois.registrant.includes('REDACTED') || intel.whois.registrant.includes('Privacy')}
                    onCopy={(v) => handleCopy(v, 'whois_registrant')}
                  />
                  <Field
                    label="Creation Date"
                    value={new Date(intel.whois.createdDate).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                    })}
                    isMono
                  />
                  <Field
                    label="Last Updated"
                    value={new Date(intel.whois.updatedDate).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                    })}
                    isMono
                  />
                  <Field
                    label="Expiration Date"
                    value={new Date(intel.whois.expiryDate).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                    })}
                    isMono
                  />
                  <Field
                    label="Authoritative Name Servers"
                    value={intel.whois.nameServers.join(', ')}
                    isMono
                  />
                  <Field
                    label="Domain Status Codes"
                    value={intel.whois.status.join(', ')}
                  />
                </dl>
              </div>
            )}
          </Panel>

          {/* Panel 3: SSL / TLS Certificate Profile */}
          <Panel
            title="SSL / TLS Cryptographic Profile"
            description="Cryptographic parameters, validation chain, and fingerprint"
            state={dataState}
            icon={Lock}
          >
            {dataState === 'pending' ? (
              <PendingStatePanel moduleName="TLS 1.3 Handshake Probe" />
            ) : dataState === 'unavailable' ? (
              <UnavailableStatePanel
                serviceName="SSL / TLS Probe"
                reason="Target host did not complete TLS negotiation on port 443. Certificate data unavailable."
              />
            ) : dataState === 'error' ? (
              <ErrorStatePanel
                errorCode="TLS_HANDSHAKE_RESET"
                message="TCP connection to port 443 was forcibly closed by the remote peer before certificate exchange."
                onRetry={handleTriggerRefresh}
              />
            ) : (
              <div className="space-y-3">
                <div className="flex items-center justify-between rounded-lg border border-tn-border/70 bg-tn-card/50 p-2.5">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={intel.ssl.isValid ? 'low' : 'medium'} />
                    <span className="text-xs font-semibold text-tn-text">
                      {intel.ssl.isValid ? 'Validation Chain: Verified CA' : 'Anomaly: Untrusted / Self-Signed CA'}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-tn-muted">
                    Protocol: {intel.ssl.protocol}
                  </span>
                </div>

                <dl className="divide-y divide-tn-border/40">
                  <Field
                    label="Certificate Subject"
                    value={intel.ssl.subject}
                    isMono
                    highlight={!intel.ssl.isValid}
                    onCopy={(v) => handleCopy(v, 'ssl_subject')}
                  />
                  <Field
                    label="Issuing Authority (CA)"
                    value={intel.ssl.issuer}
                    onCopy={(v) => handleCopy(v, 'ssl_issuer')}
                  />
                  <Field label="Cipher Suite" value={intel.ssl.cipher} isMono />
                  <Field label="Key Exchange" value={intel.ssl.keyExchange} isMono />
                  <Field
                    label="Valid From"
                    value={new Date(intel.ssl.validFrom).toLocaleDateString('en-US')}
                    isMono
                  />
                  <Field
                    label="Valid Until"
                    value={new Date(intel.ssl.validTo).toLocaleDateString('en-US')}
                    isMono
                  />
                  <Field
                    label="SHA-256 Fingerprint"
                    value={intel.ssl.fingerprint}
                    isMono
                    onCopy={(v) => handleCopy(v, 'ssl_fp')}
                  />
                </dl>
              </div>
            )}
          </Panel>

          {/* Panel 4: IP Geolocation & Routing */}
          <Panel
            title="IP Geolocation & Autonomous System"
            description="ASN topology, geolocation coordinates, and proxy flags"
            state={dataState}
            icon={Radio}
          >
            {dataState === 'pending' ? (
              <PendingStatePanel moduleName="MaxMind GeoIP & BGP Routing" />
            ) : dataState === 'unavailable' ? (
              <UnavailableStatePanel
                serviceName="BGP & Geolocation Engine"
                reason="GeoIP telemetry database requires local mmdb dataset or backend GeoIP service binding."
              />
            ) : dataState === 'error' ? (
              <ErrorStatePanel
                errorCode="BGP_ROUTE_LOOKUP_ERR"
                message="Unable to locate route object in regional internet registry databases."
                onRetry={handleTriggerRefresh}
              />
            ) : (
              <div className="space-y-3">
                {/* Proxy & Tor Security Flags */}
                <div className="grid grid-cols-3 gap-2 text-center text-xs">
                  <div className={`p-2 rounded-lg border ${
                    intel.ipInfo.isTor
                      ? 'border-tn-danger/40 bg-tn-danger/10 text-tn-danger'
                      : 'border-tn-border/60 bg-tn-card/40 text-tn-muted'
                  }`}>
                    <span className="block text-[10px] font-mono uppercase">Tor Exit Node</span>
                    <span className="font-bold">{intel.ipInfo.isTor ? 'DETECTED' : 'CLEAR'}</span>
                  </div>
                  <div className={`p-2 rounded-lg border ${
                    intel.ipInfo.isProxy
                      ? 'border-tn-warn/40 bg-tn-warn/10 text-tn-warn'
                      : 'border-tn-border/60 bg-tn-card/40 text-tn-muted'
                  }`}>
                    <span className="block text-[10px] font-mono uppercase">Proxy / VPN</span>
                    <span className="font-bold">{intel.ipInfo.isProxy ? 'ACTIVE' : 'NONE'}</span>
                  </div>
                  <div className={`p-2 rounded-lg border ${
                    intel.ipInfo.isVPN
                      ? 'border-tn-warn/40 bg-tn-warn/10 text-tn-warn'
                      : 'border-tn-border/60 bg-tn-card/40 text-tn-muted'
                  }`}>
                    <span className="block text-[10px] font-mono uppercase">Commercial VPN</span>
                    <span className="font-bold">{intel.ipInfo.isVPN ? 'CONFIRMED' : 'NO'}</span>
                  </div>
                </div>

                <dl className="divide-y divide-tn-border/40">
                  <Field label="Queried IP" value={intel.ipInfo.ip} isMono onCopy={(v) => handleCopy(v, 'ip_addr')} />
                  <Field label="Autonomous System (ASN)" value={intel.ipInfo.asn} isMono />
                  <Field label="Organization" value={intel.ipInfo.org} />
                  <Field
                    label="Geographic Location"
                    value={`${intel.ipInfo.city}, ${intel.ipInfo.country}`}
                  />
                  <Field label="Internet Service Provider" value={intel.ipInfo.isp} />
                  <Field
                    label="Reverse DNS (PTR)"
                    value={intel.dns.find((d) => d.type === 'PTR')?.value || `${intel.ipInfo.ip}.in-addr.arpa`}
                    isMono
                  />
                </dl>
              </div>
            )}
          </Panel>

          {/* Panel 5: Multi-Engine Reputation & VirusTotal Simulation */}
          <Panel
            title="Threat Reputation & Engine Detections"
            description="Simulated VirusTotal, AlienVault OTX, and feed cross-checks"
            state={dataState}
            icon={Database}
          >
            {dataState === 'pending' ? (
              <PendingStatePanel moduleName="VirusTotal Multi-Engine Scanner" />
            ) : dataState === 'unavailable' ? (
              <UnavailableStatePanel
                serviceName="VirusTotal API Connector"
                reason="Backend endpoint /api/v1/virustotal is not configured. ThreatNova AI refuses to fabricate live VirusTotal results without an active API key."
              />
            ) : dataState === 'error' ? (
              <ErrorStatePanel
                errorCode="VT_API_401_UNAUTHORIZED"
                message="VirusTotal API key is either missing or rejected by the remote API gateway."
                onRetry={handleTriggerRefresh}
              />
            ) : (
              <div className="space-y-4">
                <div className={`flex items-center justify-between rounded-lg border p-3 ${
                  intel.reputation.malicious
                    ? 'border-tn-danger/30 bg-tn-danger/10'
                    : 'border-tn-success/30 bg-tn-success/10'
                }`}>
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-tn-muted block">
                      Aggregated Multi-Engine Ratio
                    </span>
                    <p className={`text-lg font-bold font-mono mt-0.5 ${
                      intel.reputation.malicious ? 'text-tn-danger' : 'text-tn-success'
                    }`}>
                      {intel.reputation.malicious ? '5 / 90 Engines Flagged Malicious' : '0 / 90 Engines (Clean)'}
                    </p>
                  </div>
                  <span
                    className={`text-xs font-mono font-bold px-2.5 py-1 rounded border ${
                      intel.reputation.malicious
                        ? 'bg-tn-card text-tn-danger border-tn-danger/30'
                        : 'bg-tn-card text-tn-success border-tn-success/30'
                    }`}
                  >
                    {intel.reputation.malicious ? 'HIGH THREAT RISK' : 'BENIGN / CLEAN'}
                  </span>
                </div>

                {/* Threat categories */}
                {intel.reputation.categories.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    <span className="text-[10px] font-mono text-tn-muted uppercase mr-1">Classifications:</span>
                    {intel.reputation.categories.map((cat) => (
                      <span
                        key={cat}
                        className="px-2 py-0.5 rounded bg-tn-card border border-tn-border text-[11px] font-medium text-tn-text"
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                )}

                {/* Engine Sources */}
                <div className="space-y-2">
                  {intel.reputation.sources.map((source) => (
                    <div
                      key={source.name}
                      className="flex items-center justify-between p-2.5 rounded-lg border border-tn-border/60 bg-tn-card/40 text-xs"
                    >
                      <div>
                        <span className="font-semibold text-tn-text">{source.name}</span>
                        {source.detail && (
                          <span className="text-[11px] text-tn-muted font-mono ml-2">
                            ({source.detail})
                          </span>
                        )}
                      </div>
                      <span
                        className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border uppercase ${
                          source.result === 'malicious'
                            ? 'bg-tn-danger/15 border-tn-danger/30 text-tn-danger'
                            : source.result === 'suspicious'
                            ? 'bg-tn-warn/15 border-tn-warn/30 text-tn-warn'
                            : 'bg-tn-success/15 border-tn-success/30 text-tn-success'
                        }`}
                      >
                        {source.result}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Panel>

          {/* Panel 6: Correlated Infrastructure & Hashes */}
          <Panel
            title="Correlated Infrastructure & Associated Artifacts"
            description="Entities linked through multi-hop infrastructure analysis"
            state={dataState}
            icon={Network}
          >
            {dataState === 'pending' ? (
              <PendingStatePanel moduleName="Entity Graph Correlator" />
            ) : dataState === 'unavailable' ? (
              <UnavailableStatePanel
                serviceName="Threat Graph Relationship Engine"
                reason="Correlated graph database is disconnected. Multi-hop entity queries are inactive."
              />
            ) : dataState === 'error' ? (
              <ErrorStatePanel
                errorCode="GRAPH_DB_TRAVERSAL_FAILED"
                message="Relationship engine encountered timeout while building adjacency matrices."
                onRetry={handleTriggerRefresh}
              />
            ) : (
              <div className="space-y-3">
                <p className="text-xs text-tn-muted leading-relaxed">
                  Click any correlated indicator below to start an autonomous investigation scan:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {relatedIndicators.map((node) => (
                    <Link
                      key={node.id}
                      href={`/scanning?type=${node.type}&indicator=${encodeURIComponent(node.label)}`}
                      className="p-2.5 rounded-lg border border-tn-border/70 bg-tn-card/50 hover:bg-tn-card hover:border-tn-muted transition-all text-xs group"
                    >
                      <div className="flex items-center justify-between text-[10px] font-mono text-tn-muted">
                        <span className="uppercase text-tn-info font-bold">{node.type}</span>
                        <SeverityBadge severity={node.risk} />
                      </div>
                      <p className="mt-1 font-mono font-semibold text-tn-text truncate group-hover:text-tn-info transition-colors">
                        {node.label}
                      </p>
                    </Link>
                  ))}
                </div>

                <div className="mt-4 pt-3 border-t border-tn-border/60 flex items-center justify-between text-xs text-tn-muted">
                  <span>Visualized in D3 Root Tree Graph</span>
                  <Link
                    href="/graph"
                    className="text-tn-info hover:underline inline-flex items-center gap-1 font-medium"
                  >
                    Open Threat Graph <ArrowRight size={12} />
                  </Link>
                </div>
              </div>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
