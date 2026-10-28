'use client';

import { useEffect, useMemo, useState, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { detectType, MOCK_SCORES } from '@/lib/threatEngine';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  FileSearch,
  Globe2,
  Layers,
  MapPin,
  Network,
  Radio,
  Search,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import AIThreatAnalyst from '@/components/AIThreatAnalyst';
import InvestigationGraph from '@/components/InvestigationGraph';
import InvestigationOriginMap from '@/components/InvestigationOriginMap';
import PageHeader from '@/components/PageHeader';
import RiskGauge from '@/components/RiskGauge';
import SeverityBadge from '@/components/SeverityBadge';
import StatCard from '@/components/StatCard';
import {
  createDemoHistory,
  createDemoInvestigation,
} from '@/lib/demo-data';
import {
  indicatorPlaceholders,
  indicatorTypeLabel,
  indicatorTypes,
  isIndicatorType,
  isValidIndicator,
  sampleDemonstrationIndicators,
} from '@/lib/indicators';
import { getSavedInvestigations } from '@/lib/storage';
import { fetchInvestigation, fetchInvestigations, fetchDashboardStats, type DashboardStats } from '@/lib/api';
import type { IndicatorType, Investigation } from '@/lib/types';

const demoInvestigations = createDemoHistory();
const currentInvestigation = createDemoInvestigation();

const MODULE_STATUSES = [
  {
    name: 'VirusTotal API',
    category: 'Reputation Feed',
    state: 'Integration Boundary',
    stateColor: 'text-tn-warn border-tn-warn/30 bg-tn-warn/10',
    description: 'Service contract ready. Mock fixtures active in frontend demonstration.',
    icon: Database,
  },
  {
    name: 'LLM Reasoning Engine',
    category: 'AI Analysis',
    state: 'Integration Boundary',
    stateColor: 'text-tn-warn border-tn-warn/30 bg-tn-warn/10',
    description: 'Prompt synthesis contract prepared for future backend OpenAI/Anthropic/Gemini endpoints.',
    icon: Cpu,
  },
  {
    name: 'DNS & WHOIS Correlator',
    category: 'Reconnaissance',
    state: 'Demonstration Active',
    stateColor: 'text-tn-success border-tn-success/30 bg-tn-success/10',
    description: 'Passive telemetry, record fixtures, and registration schemas loaded.',
    icon: Globe2,
  },
  {
    name: 'D3 Graph Correlator',
    category: 'Relationship Graph',
    state: 'Interactive & Active',
    stateColor: 'text-tn-info border-tn-info/30 bg-tn-info/10',
    description: 'Multi-hop entity resolution and force-directed SVG clustering online.',
    icon: Network,
  },
  {
    name: 'SQLite Storage Engine',
    category: 'Persistence',
    state: 'Schema Defined',
    stateColor: 'text-tn-muted border-tn-border bg-tn-card',
    description: 'Prepared for local FastAPI backend SQLite database connection.',
    icon: Layers,
  },
];



function formatDate(date: string): string {
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
  }).format(new Date(date));
}

export default function DashboardHome({
  searchQuery,
  showCompletion,
}: {
  searchQuery: string;
  showCompletion: boolean;
}) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const rawQ = (searchParams?.get('q') || searchQuery || '').trim();
  const activeQuery = rawQ || 'suspicious-domain.test';
  const activeType = detectType(activeQuery);
  const dynamicRisk = MOCK_SCORES[activeType] || MOCK_SCORES.domain;

  const [type, setType] = useState<IndicatorType>('domain');
  const [indicator, setIndicator] = useState('');
  const [error, setError] = useState('');
  const [investigationsList, setInvestigationsList] = useState<Investigation[]>(demoInvestigations);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string>(
    demoInvestigations[0]?.id || '',
  );
  const [selectedInvestigationFull, setSelectedInvestigationFull] = useState<Investigation | null>(null);
  const [isLoadingInvestigations, setIsLoadingInvestigations] = useState<boolean>(false);
  const [stats, setStats] = useState<DashboardStats>({
    totalInvestigations: 0,
    completedInvestigations: 0,
    activeScans: 0,
    highRiskAlerts: 0,
    correlatedEntities: 0,
    findingsBySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
  });

  // Synchronize saved investigations and live backend investigations
  useEffect(() => {
    let isMounted = true;

    async function loadInvestigationsData() {
      setIsLoadingInvestigations(true);

      // 1. Read locally saved investigations from localStorage
      const saved = getSavedInvestigations();

      // 2. Query backend SQLite database for live investigations
      let backendList: Investigation[] = [];
      try {
        backendList = await fetchInvestigations(50, 0);
      } catch (err) {
        console.debug('Backend offline or unreachable, using local store:', err);
      }

      if (!isMounted) return;

      // Merge: backend investigations > saved local investigations > demoInvestigations
      const mergedMap = new Map<string, Investigation>();
      for (const inv of backendList) {
        mergedMap.set(inv.id, inv);
      }
      for (const inv of saved) {
        if (!mergedMap.has(inv.id)) {
          mergedMap.set(inv.id, inv);
        }
      }
      for (const inv of demoInvestigations) {
        if (!mergedMap.has(inv.id)) {
          mergedMap.set(inv.id, inv);
        }
      }

      const combined = Array.from(mergedMap.values());
      setInvestigationsList(combined);
      setIsLoadingInvestigations(false);

      // 3. Query backend SQLite database for aggregated scoreboard metrics
      try {
        const liveStats = await fetchDashboardStats();
        if (liveStats && isMounted) {
          setStats(liveStats);
        } else if (isMounted) {
          // Fallback: truthful computation from persisted records without fake demo numbers
          const sourceList = backendList.length > 0 ? backendList : saved;
          const completedCount = sourceList.filter((i) => i.status === 'complete').length;
          const highRiskCount = sourceList.filter(
            (i) => i.risk?.level === 'critical' || i.risk?.level === 'high' || (i.risk?.score ?? 0) >= 60,
          ).length;

          const entitiesSet = new Set<string>();
          for (const inv of sourceList) {
            if (inv.query) entitiesSet.add(inv.query.trim().toLowerCase());
            if (Array.isArray(inv.graphData?.nodes)) {
              for (const n of inv.graphData.nodes) {
                if (n.label) entitiesSet.add(String(n.label).trim().toLowerCase());
                else if (n.id) entitiesSet.add(String(n.id).trim().toLowerCase());
              }
            }
          }

          setStats({
            totalInvestigations: sourceList.length,
            completedInvestigations: completedCount,
            activeScans: sourceList.filter((i) => i.status === 'scanning').length,
            highRiskAlerts: highRiskCount,
            correlatedEntities: entitiesSet.size,
            findingsBySeverity: {
              critical: sourceList.reduce(
                (acc, inv) => acc + (inv.findings?.filter((f) => f.severity === 'critical').length || 0),
                0,
              ),
              high: sourceList.reduce(
                (acc, inv) => acc + (inv.findings?.filter((f) => f.severity === 'high').length || 0),
                0,
              ),
              medium: sourceList.reduce(
                (acc, inv) => acc + (inv.findings?.filter((f) => f.severity === 'medium').length || 0),
                0,
              ),
              low: sourceList.reduce(
                (acc, inv) => acc + (inv.findings?.filter((f) => f.severity === 'low').length || 0),
                0,
              ),
              info: sourceList.reduce(
                (acc, inv) => acc + (inv.findings?.filter((f) => f.severity === 'info').length || 0),
                0,
              ),
            },
          });
        }
      } catch (err) {
        console.debug('Failed to fetch dashboard stats:', err);
      }

      // If searchQuery is present, prioritize selecting the investigation matching query
      if (searchQuery.trim()) {
        const norm = searchQuery.trim().toLowerCase();
        const match = combined.find(
          (inv) => inv.query.toLowerCase() === norm || inv.id.toLowerCase() === norm,
        );
        if (match) {
          setSelectedInvestigationId(match.id);
        }
      }
    }

    loadInvestigationsData();

    return () => {
      isMounted = false;
    };
  }, [searchQuery, showCompletion]);

  // Fetch full investigation details (findings, domainIntel, graphNodes) when selected
  useEffect(() => {
    let isMounted = true;
    if (!selectedInvestigationId) return;

    const matched = investigationsList.find((i) => i.id === selectedInvestigationId);
    if (matched && Array.isArray(matched.findings) && matched.findings.length > 0) {
      setSelectedInvestigationFull(matched);
      return;
    }

    fetchInvestigation(selectedInvestigationId)
      .then((fullInv) => {
        if (!isMounted || !fullInv) return;
        setSelectedInvestigationFull(fullInv);
        setInvestigationsList((prev) =>
          prev.map((item) => (item.id === fullInv.id ? fullInv : item))
        );
      })
      .catch((err) => {
        console.debug('Failed to fetch full investigation detail:', err);
      });

    return () => {
      isMounted = false;
    };
  }, [selectedInvestigationId]);

  const normalizedQuery = searchQuery.trim().toLowerCase();

  const visibleInvestigations = useMemo(
    () =>
      investigationsList.filter(
        (investigation) =>
          !normalizedQuery ||
          investigation.query.toLowerCase().includes(normalizedQuery) ||
          indicatorTypeLabel(investigation.type).toLowerCase().includes(normalizedQuery) ||
          investigation.risk.level.toLowerCase().includes(normalizedQuery),
      ),
    [investigationsList, normalizedQuery],
  );

  const selectedInvestigation = useMemo(
    () => {
      if (selectedInvestigationFull && selectedInvestigationFull.id === selectedInvestigationId) {
        return selectedInvestigationFull;
      }
      return (
        visibleInvestigations.find((inv) => inv.id === selectedInvestigationId) ||
        investigationsList.find((inv) => inv.id === selectedInvestigationId) ||
        visibleInvestigations[0] ||
        investigationsList[0]
      );
    },
    [selectedInvestigationId, selectedInvestigationFull, visibleInvestigations, investigationsList],
  );

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = indicator.trim();

    if (!query) {
      setError('Please enter an indicator to start the investigation.');
      return;
    }
    if (!isValidIndicator(query, type)) {
      setError(`Invalid ${indicatorTypeLabel(type).toLowerCase()} format. Check syntax or try a sample indicator.`);
      return;
    }

    const params = new URLSearchParams({ type, indicator: query });
    router.push(`/scanning?${params.toString()}`);
  }

  function handleSelectSample(sample: (typeof sampleDemonstrationIndicators)[0]) {
    setType(sample.type);
    setIndicator(sample.value);
    setError('');
  }

  const summaryCards = [
    {
      icon: FileSearch,
      label: 'Indicators Investigated',
      value: stats.totalInvestigations,
      detail:
        stats.totalInvestigations === 1
          ? '1 investigation in database'
          : `${stats.totalInvestigations} investigations in database`,
      accent: 'text-tn-info',
    },
    {
      icon: ShieldAlert,
      label: 'High-Risk Alerts',
      value: stats.highRiskAlerts,
      detail: 'Critical & High signals',
      accent: 'text-tn-danger',
    },
    {
      icon: Network,
      label: 'Correlated Entities',
      value: stats.correlatedEntities,
      detail: 'Graph nodes across campaigns',
      accent: 'text-tn-info',
    },
    {
      icon: CheckCircle2,
      label: 'Completed Investigations',
      value:
        stats.totalInvestigations > 0
          ? `${stats.completedInvestigations} / ${stats.totalInvestigations}`
          : '0 / 0',
      detail:
        stats.totalInvestigations > 0
          ? `${Math.round((stats.completedInvestigations / stats.totalInvestigations) * 100)}% triage closure`
          : '0% triage closure',
      accent: 'text-tn-success',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Investigation Overview Dashboard"
        subtitle="Autonomous Threat Investigation & Early-Warning System for HackIndia × KIT Hackathon 2026."
      >
        <span className="inline-flex items-center gap-2 rounded-md border border-tn-warn/30 bg-tn-warn/10 px-2.5 py-1.5 text-[10px] font-semibold tracking-wide text-tn-warn font-mono">
          <span className="h-1.5 w-1.5 rounded-full bg-tn-warn animate-pulse" aria-hidden="true" />
          DEMO WORKSPACE
        </span>
      </PageHeader>

      {/* Completion Banner */}
      {showCompletion && (
        <div
          role="status"
          className="flex flex-col gap-3 rounded-xl border border-tn-success/30 bg-tn-success/10 px-5 py-4 sm:flex-row sm:items-center sm:justify-between shadow-lg"
        >
          <div className="flex items-start gap-3 text-sm text-tn-text">
            <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-tn-success" aria-hidden="true" />
            <div>
              <p className="font-semibold text-tn-text">Demonstration Scan Completed Successfully</p>
              <p className="text-xs text-tn-muted mt-0.5">
                The 6-stage investigation pipeline simulated format validation, reputation cross-checks, network recon, and AI risk synthesis.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Link
              href="/graph"
              className="px-3 py-1.5 rounded-lg border border-tn-border bg-tn-surface text-xs font-medium text-tn-text hover:bg-tn-card transition-colors"
            >
              Inspect Threat Graph
            </Link>
            <Link
              href="/dashboard"
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-tn-muted hover:text-tn-text"
            >
              Dismiss
            </Link>
          </div>
        </div>
      )}

      {/* Hero New Investigation Search Section */}
      <section
        id="new-investigation"
        aria-labelledby="new-investigation-title"
        className="relative overflow-hidden rounded-2xl border border-tn-border bg-tn-surface p-5 sm:p-8 shadow-xl"
      >
        {/* Subtle decorative background circles */}
        <div className="pointer-events-none absolute -right-20 -top-28 h-72 w-72 rounded-full border border-tn-border/40" />
        <div className="pointer-events-none absolute -right-6 -top-14 h-48 w-48 rounded-full border border-tn-border/30" />

        <div className="relative grid gap-8 xl:grid-cols-[minmax(0,1.1fr)_minmax(380px,0.9fr)] xl:items-center">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-semibold uppercase tracking-wider text-tn-info">
              <Radio size={14} className="animate-pulse" />
              <span>ThreatNova AI · Early-Warning Engine</span>
            </div>
            <h2 className="mt-3 text-2xl font-bold tracking-tight text-tn-text sm:text-3xl">
              Autonomous Threat Investigation.
              <span className="block text-tn-muted font-normal text-xl sm:text-2xl mt-1">
                Deep signal correlation &amp; early warning.
              </span>
            </h2>
            <p className="mt-3 max-w-xl text-sm leading-relaxed text-tn-muted">
              Submit an IP address, domain, URL, file hash, email, or threat actor handle. ThreatNova AI coordinates multi-source validation, passive intelligence enrichment, and explainable risk analysis.
            </p>

            {/* Quick Demonstration Samples */}
            <div className="mt-5">
              <span className="text-[11px] font-mono text-tn-muted uppercase tracking-wider block mb-2">
                1-Click Sample Indicators:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {sampleDemonstrationIndicators.map((sample) => (
                  <button
                    key={sample.value}
                    type="button"
                    onClick={() => handleSelectSample(sample)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-tn-border bg-tn-card/80 hover:bg-tn-border/70 hover:border-tn-muted px-2.5 py-1 text-xs text-tn-text transition-all font-mono"
                    title={`Click to test ${sample.label}`}
                  >
                    <span className="text-[10px] text-tn-info font-sans">[{indicatorTypeLabel(sample.type)}]</span>
                    <span className="truncate max-w-[130px]">{sample.value}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Investigation Submission Form */}
          <form
            onSubmit={handleSubmit}
            noValidate
            className="relative rounded-xl border border-tn-border bg-tn-bg/90 p-5 shadow-2xl"
          >
            <div className="mb-4 flex items-center justify-between pb-3 border-b border-tn-border/70">
              <div>
                <h3 id="new-investigation-title" className="text-sm font-semibold text-tn-text">
                  New Threat Investigation
                </h3>
                <p className="text-xs text-tn-muted">Launches simulated 6-phase autonomous scan</p>
              </div>
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-tn-border bg-tn-card">
                <Search size={16} className="text-tn-info" aria-hidden="true" />
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label htmlFor="indicator-type" className="mb-1.5 block text-xs font-medium text-tn-muted">
                  Indicator Type
                </label>
                <select
                  id="indicator-type"
                  value={type}
                  onChange={(e) => {
                    const next = e.target.value;
                    if (isIndicatorType(next)) setType(next);
                    setError('');
                  }}
                  className="h-10 w-full rounded-lg border border-tn-border bg-tn-card px-3 text-sm text-tn-text focus:border-tn-muted focus:outline-none transition-colors"
                >
                  {indicatorTypes.map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="indicator-value" className="mb-1.5 block text-xs font-medium text-tn-muted">
                  Indicator Value
                </label>
                <div className="relative">
                  <Search
                    size={15}
                    aria-hidden="true"
                    className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-tn-muted"
                  />
                  <input
                    id="indicator-value"
                    type="text"
                    value={indicator}
                    onChange={(e) => {
                      setIndicator(e.target.value);
                      setError('');
                    }}
                    placeholder={indicatorPlaceholders[type]}
                    autoComplete="off"
                    spellCheck={false}
                    className="h-11 w-full rounded-lg border border-tn-border bg-tn-card pl-9 pr-3 font-mono text-sm text-tn-text placeholder:font-sans placeholder:text-tn-muted/50 focus:border-tn-muted focus:outline-none transition-colors"
                  />
                </div>
                {error ? (
                  <p className="mt-1.5 text-xs text-tn-danger flex items-center gap-1">
                    <AlertTriangle size={12} /> {error}
                  </p>
                ) : (
                  <p className="mt-1.5 text-[11px] text-tn-muted">
                    Format validation only. No live queries or sensitive data sent.
                  </p>
                )}
              </div>

              <button
                type="submit"
                className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg border border-tn-muted/40 bg-tn-card px-4 text-sm font-semibold text-tn-text hover:bg-tn-border hover:border-tn-muted transition-all cursor-pointer shadow-md group"
              >
                <Zap size={16} className="text-tn-warn group-hover:scale-110 transition-transform" />
                <span>Investigate Threat</span>
                <ArrowRight size={15} className="group-hover:translate-x-1 transition-transform" />
              </button>
            </div>
          </form>
        </div>
      </section>

      {/* Demonstration Notice */}
      <div
        role="note"
        className="flex items-start gap-3 rounded-xl border border-tn-border bg-tn-surface px-4 py-3 text-xs leading-relaxed text-tn-muted"
      >
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-tn-warn" aria-hidden="true" />
        <p>
          <strong className="text-tn-text">Demonstration Data Notice:</strong> All scores, findings, telemetry logs, and relationship graphs on this platform are demonstration fixtures for HackIndia × KIT Hackathon 2026. Higher scores represent higher simulated risk.
        </p>
      </div>

      {/* Workspace Summary Stats */}
      <section aria-label="Workspace metrics">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-tn-text">Platform Telemetry Overview</h2>
          <span className="text-[11px] font-mono text-tn-muted">Live SQLite Metrics</span>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {summaryCards.map(({ icon, label, value, detail, accent }) => (
            <StatCard
              key={label}
              icon={icon}
              label={label}
              value={value}
              detail={detail}
              accent={accent}
            />
          ))}
        </div>
      </section>

      {/* Current Active Investigation Summary + Risk Explanation */}
      <section className="rounded-xl border border-tn-border bg-tn-surface p-5 sm:p-6 shadow-md">
        <div className="flex flex-col gap-2 border-b border-tn-border pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-semibold uppercase tracking-wider text-tn-info">
                Active Benchmark Investigation
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-tn-card border border-tn-border text-tn-muted">
                {currentInvestigation.id}
              </span>
            </div>
            <h3 className="mt-1 font-mono text-lg font-bold text-tn-text">
              {activeQuery}
            </h3>
          </div>
          <div className="flex items-center gap-3">
            <SeverityBadge severity={dynamicRisk.level} />
            <Link
              href="/findings"
              className="inline-flex items-center gap-1.5 rounded-lg border border-tn-border bg-tn-card px-3 py-1.5 text-xs font-medium text-tn-text hover:border-tn-muted transition-colors"
            >
              Full Evidence <ArrowRight size={13} />
            </Link>
          </div>
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-[160px_minmax(0,1fr)_minmax(0,1fr)] items-start">
          {/* Risk Gauge */}
          <div className="flex flex-col items-center justify-center p-3 rounded-xl border border-tn-border/70 bg-tn-bg/50">
            <RiskGauge score={dynamicRisk.score} size={110} label="Risk Score" />
            <div className="mt-2 text-center">
              <span className="text-[10px] font-mono uppercase tracking-wider text-tn-muted block">
                Confidence
              </span>
              <span className="text-xs font-mono font-bold text-tn-info">
                {dynamicRisk.confidence}% Verified
              </span>
            </div>
          </div>

          {/* Contributing Risk Factors */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-tn-text uppercase tracking-wider font-mono">
              Contributing Risk Factors
            </h4>
            <div className="space-y-2">
              {dynamicRisk.factors.map((factor) => (
                <div
                  key={factor.name}
                  className="rounded-lg border border-tn-border/60 bg-tn-card/40 p-2.5 text-xs"
                >
                  <div className="flex items-center justify-between font-medium">
                    <span className="text-tn-text">{factor.name}</span>
                    <span className="font-mono text-tn-danger">+{factor.pts} pts</span>
                  </div>
                  <p className="mt-1 text-[11px] text-tn-muted">{factor.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* AI Explanation & Findings Breakdown */}
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-tn-text uppercase tracking-wider font-mono">
                  Autonomous Threat Synthesis
                </h4>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-tn-warn/10 text-tn-warn border border-tn-warn/25">
                  AI INTERPRETATION
                </span>
              </div>
              <p className="mt-2 rounded-lg border border-tn-border/60 bg-tn-bg/60 p-3 text-xs leading-relaxed text-tn-muted">
                {dynamicRisk.explanation}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-tn-text uppercase tracking-wider font-mono mb-2">
                Findings by Severity
              </h4>
              <div className="flex flex-wrap gap-2">
                {Object.entries(stats.findingsBySeverity).map(([sev, count]) => (
                  <span
                    key={sev}
                    className="inline-flex items-center gap-1.5 rounded-md border border-tn-border bg-tn-card px-2.5 py-1 text-xs"
                  >
                    <span
                      className={`h-2 w-2 rounded-full ${
                        sev === 'critical'
                          ? 'bg-tn-danger'
                          : sev === 'high'
                          ? 'bg-tn-warn'
                          : sev === 'medium'
                          ? 'bg-tn-warn/80'
                          : 'bg-tn-success'
                      }`}
                    />
                    <span className="capitalize text-tn-text font-mono text-[11px]">{sev}: {count}</span>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Threat Graph Preview & Domain Intelligence Dual Section */}
      <div className="grid gap-6 xl:grid-cols-2">
        {/* Threat Graph Preview */}
        <section
          aria-labelledby="threat-graph-preview-title"
          className="rounded-xl border border-tn-border bg-tn-surface p-5 shadow-md flex flex-col"
        >
          <div className="flex items-start justify-between pb-3 border-b border-tn-border">
            <div>
                <h3 id="threat-graph-preview-title" className="text-sm font-semibold text-tn-text flex items-center gap-2">
                  <Network size={16} className="text-tn-info" />
                  Threat Intelligence Graph Preview
                </h3>
                <p className="mt-0.5 text-xs text-tn-muted">
                  Hierarchical Root Tree visualization (Target → Categories → Findings)
                </p>
              </div>
              <Link
                href="/graph"
                className="inline-flex items-center gap-1 text-xs text-tn-info hover:text-tn-text transition-colors"
              >
                Interactive Canvas <ArrowRight size={13} />
              </Link>
            </div>

            <div className="mt-3 flex-1 flex items-center justify-center rounded-lg border border-tn-border/70 bg-tn-bg/60 p-2">
              <InvestigationGraph investigation={selectedInvestigation} />
            </div>

            <div className="mt-3 flex items-center justify-between text-xs text-tn-muted border-t border-tn-border/60 pt-3 font-mono">
              <span>{selectedInvestigation?.findings?.length || 0} telemetry findings mapped</span>
              <Link href="/graph" className="text-tn-info hover:underline text-[11px]">
                Explore Full Entity Graph →
              </Link>
            </div>
        </section>

        {/* Domain & Network Intelligence Snapshot */}
        <section
          aria-labelledby="network-intel-title"
          className="rounded-xl border border-tn-border bg-tn-surface p-5 shadow-md flex flex-col"
        >
          <div className="flex items-start justify-between pb-3 border-b border-tn-border">
            <div>
              <h3 id="network-intel-title" className="text-sm font-semibold text-tn-text flex items-center gap-2">
                <Globe2 size={16} className="text-tn-info" />
                Network Reconnaissance Telemetry
              </h3>
              <p className="mt-0.5 text-xs text-tn-muted">
                DNS, WHOIS, TLS Certificate, and Routing profile
              </p>
            </div>
            <Link
              href="/intelligence"
              className="inline-flex items-center gap-1 text-xs text-tn-info hover:text-tn-text transition-colors"
            >
              Full Diagnostics <ArrowRight size={13} />
            </Link>
          </div>

          <div className="mt-3 grid grid-cols-2 gap-2.5 flex-1">
            <div className="rounded-lg border border-tn-border/60 bg-tn-card/50 p-3">
              <span className="text-[10px] font-mono uppercase text-tn-muted block">DNS Status</span>
              <p className="text-xs font-semibold text-tn-text mt-1">6 Records Loaded</p>
              <p className="text-[11px] text-tn-muted mt-0.5 font-mono">A, AAAA, MX, NS, TXT</p>
            </div>
            <div className="rounded-lg border border-tn-border/60 bg-tn-card/50 p-3">
              <span className="text-[10px] font-mono uppercase text-tn-muted block">WHOIS Registrar</span>
              <p className="text-xs font-semibold text-tn-text mt-1">NameCheap Inc.</p>
              <p className="text-[11px] text-tn-muted mt-0.5 font-mono">Privacy Protected</p>
            </div>
            <div className="rounded-lg border border-tn-border/60 bg-tn-card/50 p-3">
              <span className="text-[10px] font-mono uppercase text-tn-muted block">SSL / TLS Certificate</span>
              <p className="text-xs font-semibold text-tn-warn mt-1">Self-Signed CA</p>
              <p className="text-[11px] text-tn-muted mt-0.5 font-mono">Subject Mismatch</p>
            </div>
            <div className="rounded-lg border border-tn-border/60 bg-tn-card/50 p-3">
              <span className="text-[10px] font-mono uppercase text-tn-muted block">IP Geolocation</span>
              <p className="text-xs font-semibold text-tn-text mt-1">192.0.2.1 · ASN 64496</p>
              <p className="text-[11px] text-tn-muted mt-0.5 font-mono">Tor Exit Node match</p>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-xs text-tn-muted border-t border-tn-border/60 pt-3 font-mono">
            <span>Detection: 5/90 engines</span>
            <Link href="/intelligence" className="text-tn-info hover:underline text-[11px]">
              View All Protocol Panels →
            </Link>
          </div>
        </section>
      </div>

      {/* Module Architecture Status Panel */}
      <section className="rounded-xl border border-tn-border bg-tn-surface p-5 shadow-md">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-3 border-b border-tn-border">
          <div>
            <h3 className="text-sm font-semibold text-tn-text flex items-center gap-2">
              <Cpu size={16} className="text-tn-info" />
              Investigation Engine Modules &amp; Integration Boundaries
            </h3>
            <p className="text-xs text-tn-muted mt-0.5">
              Current operational readiness for future Python/FastAPI backend, VirusTotal API, and LLM services
            </p>
          </div>
          <Link
            href="/settings"
            className="text-xs text-tn-muted hover:text-tn-text font-mono underline"
          >
            Configure Settings
          </Link>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {MODULE_STATUSES.map((mod) => {
            const Icon = mod.icon;
            return (
              <div
                key={mod.name}
                className="rounded-lg border border-tn-border/70 bg-tn-card/40 p-3.5 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-tn-text flex items-center gap-1.5">
                      <Icon size={14} className="text-tn-muted" />
                      {mod.name}
                    </span>
                    <span
                      className={`text-[9px] font-mono font-semibold px-2 py-0.5 rounded border ${mod.stateColor}`}
                    >
                      {mod.state}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-tn-muted leading-relaxed">
                    {mod.description}
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-tn-border/40 text-[10px] font-mono text-tn-muted">
                  Category: {mod.category}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Recent Investigations History Table */}
      <section
        aria-labelledby="recent-investigations-title"
        className="overflow-hidden rounded-xl border border-tn-border bg-tn-surface shadow-md"
      >
        <div className="flex flex-col gap-2 border-b border-tn-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 id="recent-investigations-title" className="text-sm font-semibold text-tn-text">
              Recent Investigations
            </h3>
            <p className="mt-0.5 text-xs text-tn-muted">
              Searchable history of historical demonstration cases across all indicator formats.
            </p>
          </div>
          <Link
            href="/history"
            className="inline-flex w-fit items-center gap-1.5 rounded-lg border border-tn-border bg-tn-card px-3 py-1.5 text-xs font-medium text-tn-text hover:border-tn-muted transition-colors"
          >
            <Clock3 size={13} />
            Full History Archive
          </Link>
        </div>

        {normalizedQuery && (
          <div className="border-b border-tn-border/70 px-5 py-2.5 text-xs text-tn-muted">
            Filtered by <span className="font-medium text-tn-text">&ldquo;{searchQuery.trim()}&rdquo;</span>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px] text-left">
            <thead className="bg-tn-card/50">
              <tr className="text-[10px] font-mono uppercase tracking-wider text-tn-muted">
                <th scope="col" className="px-5 py-3">Indicator</th>
                <th scope="col" className="px-3 py-3">Type</th>
                <th scope="col" className="px-3 py-3">Date</th>
                <th scope="col" className="px-3 py-3">Risk Assessment</th>
                <th scope="col" className="px-3 py-3">Confidence</th>
                <th scope="col" className="px-5 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-tn-border/70">
              {visibleInvestigations.map((inv) => {
                const isSelected = selectedInvestigation?.id === inv.id;
                return (
                  <tr
                    key={inv.id}
                    onClick={() => setSelectedInvestigationId(inv.id)}
                    className={`text-xs transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-tn-card/75 border-l-2 border-l-tn-info'
                        : 'hover:bg-tn-card/30'
                    }`}
                  >
                    <td className="max-w-64 px-5 py-3.5 font-mono text-tn-text">
                      <span className="block truncate font-medium">{inv.query}</span>
                    </td>
                    <td className="px-3 py-3.5">
                      <span className="rounded bg-tn-card border border-tn-border px-2 py-0.5 text-[10px] font-mono text-tn-info">
                        {indicatorTypeLabel(inv.type)}
                      </span>
                    </td>
                    <td className="px-3 py-3.5 text-tn-muted font-mono">{formatDate(inv.startedAt)}</td>
                    <td className="px-3 py-3.5">
                      <span className="inline-flex items-center gap-1.5">
                        <span
                          className={`h-2 w-2 rounded-full ${
                            inv.risk.score >= 80
                              ? 'bg-tn-danger'
                              : inv.risk.score >= 50
                              ? 'bg-tn-warn'
                              : 'bg-tn-success'
                          }`}
                          aria-hidden="true"
                        />
                        <span className="capitalize text-tn-text font-medium">
                          {inv.risk.level} · {inv.risk.score}/100
                        </span>
                      </span>
                    </td>
                    <td className="px-3 py-3.5 font-mono text-tn-muted">
                      {inv.risk.confidence}%
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <div className="inline-flex items-center justify-end gap-2">
                        {isSelected && (
                          <span className="hidden sm:inline-flex items-center gap-1 rounded bg-tn-info/15 border border-tn-info/30 px-2 py-0.5 text-[10px] font-mono text-tn-info font-medium">
                            <MapPin size={10} />
                            Viewing Map
                          </span>
                        )}
                        <Link
                          href={`/scanning?type=${inv.type}&indicator=${encodeURIComponent(inv.query)}`}
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1 text-xs text-tn-info hover:text-tn-text font-medium"
                        >
                          Re-scan <ArrowRight size={12} />
                        </Link>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {visibleInvestigations.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center">
                    <p className="text-sm font-medium text-tn-text">No matching investigations</p>
                    <p className="mt-1 text-xs text-tn-muted">Try clearing the search query.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── AI Threat Analyst (Google Gemini Integration) ── */}
      <AIThreatAnalyst investigation={selectedInvestigation} />

      {/* ── Investigation Origin Map ── */}
      <InvestigationOriginMap
        investigation={selectedInvestigation}
        isLoading={isLoadingInvestigations}
      />

      {/* Quick Navigation Footer */}
      <section className="rounded-xl border border-tn-border bg-tn-surface/60 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
          <span className="font-semibold text-tn-text font-mono">Quick Feature Navigation:</span>
          <div className="flex flex-wrap gap-2">
            {[
              { href: '/graph', label: 'Threat Graph' },
              { href: '/findings', label: 'Findings & Evidence' },
              { href: '/intelligence', label: 'Domain & Network' },
              { href: '/history', label: 'Investigation History' },
              { href: '/alerts', label: 'Alerts Feed' },
              { href: '/settings', label: 'Settings & Architecture' },
            ].map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className="px-2.5 py-1 rounded-md border border-tn-border bg-tn-card text-tn-muted hover:text-tn-text hover:border-tn-muted transition-colors text-[11px]"
              >
                {label}
              </Link>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
