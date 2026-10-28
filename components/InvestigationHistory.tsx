'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { FileSearch, Search } from 'lucide-react';
import DemoDataBadge from '@/components/DemoDataBadge';
import EmptyState from '@/components/EmptyState';
import PageHeader from '@/components/PageHeader';
import SeverityBadge from '@/components/SeverityBadge';
import { createDemoHistory } from '@/lib/demo-data';
import { indicatorTypeLabel, indicatorTypes } from '@/lib/indicators';
import { fetchInvestigation, fetchInvestigations } from '@/lib/api';
import { getSavedInvestigations } from '@/lib/storage';
import type { IndicatorType, Investigation, Severity } from '@/lib/types';

const demoHistory = createDemoHistory();
type SortBy = 'date-desc' | 'date-asc' | 'risk-desc' | 'indicator';

function formatDate(timestamp: string): string {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(timestamp));
}

function InvestigationDetails({ investigation }: { investigation: Investigation }) {
  return (
    <section className="rounded-xl border border-tn-border bg-tn-surface p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-tn-muted">
            Sample investigation · {investigation.id}
          </p>
          <h2 className="mt-1 break-all font-mono text-sm font-semibold text-tn-text">
            {investigation.query}
          </h2>
        </div>
        <SeverityBadge severity={investigation.risk.level as Severity} />
      </div>

      <dl className="mt-4 grid gap-3 border-y border-tn-border py-3 sm:grid-cols-2 xl:grid-cols-4">
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-tn-muted">Indicator type</dt>
          <dd className="mt-1 text-xs text-tn-text">{indicatorTypeLabel(investigation.type)}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-tn-muted">Started (UTC)</dt>
          <dd className="mt-1 text-xs text-tn-text">{formatDate(investigation.startedAt)}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-tn-muted">Status</dt>
          <dd className="mt-1 capitalize text-xs text-tn-text">{investigation.status}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-tn-muted">Illustrative risk / confidence</dt>
          <dd className="mt-1 text-xs text-tn-text">
            {investigation.risk.score}/100 · {investigation.risk.confidence}%
          </dd>
        </div>
      </dl>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold text-tn-text">Sample findings</h3>
          <p className="mt-1 text-[10px] text-tn-muted">
            {investigation.findings.length} demonstration {investigation.findings.length === 1 ? 'entry' : 'entries'}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href={`/scanning?type=${investigation.type}&indicator=${encodeURIComponent(investigation.query)}`}
            className="inline-flex items-center gap-1.5 rounded-md border border-tn-border bg-tn-card px-3 py-2 text-xs font-medium text-tn-info hover:border-tn-muted transition-colors"
          >
            Re-run Pipeline
          </Link>
          <Link
            href="/findings"
            className="inline-flex items-center gap-2 rounded-md border border-tn-border bg-tn-card px-3 py-2 text-xs font-medium text-tn-text hover:border-tn-muted transition-colors"
          >
            Open findings & evidence
          </Link>
        </div>
      </div>
      {investigation.risk.explanation && (
        <p className="mt-3 rounded-lg border border-tn-border/70 bg-tn-card/50 p-3 text-xs leading-5 text-tn-muted">
          {investigation.risk.explanation}
        </p>
      )}
    </section>
  );
}

export default function InvestigationHistory({
  initialSelectedId,
}: {
  initialSelectedId: string;
}) {
  const [historyList, setHistoryList] = useState<Investigation[]>(demoHistory);
  const [selectedFull, setSelectedFull] = useState<Investigation | null>(null);
  const [isLiveBackend, setIsLiveBackend] = useState<boolean>(false);
  const [query, setQuery] = useState('');
  const [type, setType] = useState<'all' | IndicatorType>('all');
  const [status, setStatus] = useState<'all' | Investigation['status']>('all');
  const [severity, setSeverity] = useState<'all' | Severity>('all');
  const [sortBy, setSortBy] = useState<SortBy>('date-desc');
  const [selectedId, setSelectedId] = useState(initialSelectedId);

  useEffect(() => {
    let isMounted = true;
    async function loadHistory() {
      const saved = getSavedInvestigations();
      let backendItems: Investigation[] = [];
      try {
        backendItems = await fetchInvestigations(100, 0);
        if (backendItems.length > 0 && isMounted) {
          setIsLiveBackend(true);
        }
      } catch (err) {
        console.debug('Backend offline, using local store:', err);
      }

      if (!isMounted) return;

      const mergedMap = new Map<string, Investigation>();
      for (const item of backendItems) mergedMap.set(item.id, item);
      for (const item of saved) {
        if (!mergedMap.has(item.id)) mergedMap.set(item.id, item);
      }
      for (const item of demoHistory) {
        if (!mergedMap.has(item.id)) mergedMap.set(item.id, item);
      }
      const combined = Array.from(mergedMap.values());
      setHistoryList(combined);
      if (!selectedId && combined.length > 0) {
        setSelectedId(combined[0].id);
      }
    }

    loadHistory();
    return () => {
      isMounted = false;
    };
  }, []);

  // Fetch full investigation details when selected
  useEffect(() => {
    let isMounted = true;
    if (!selectedId) return;

    fetchInvestigation(selectedId)
      .then((full) => {
        if (full && isMounted) {
          setSelectedFull(full);
        }
      })
      .catch((err) => {
        console.debug('Failed to fetch full details:', err);
      });

    return () => {
      isMounted = false;
    };
  }, [selectedId]);

  const visibleHistory = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const filtered = historyList.filter((investigation) => {
      const matchesQuery =
        !normalizedQuery ||
        investigation.query.toLowerCase().includes(normalizedQuery) ||
        investigation.id.toLowerCase().includes(normalizedQuery);
      const matchesType = type === 'all' || investigation.type === type;
      const matchesStatus = status === 'all' || investigation.status === status;
      const matchesSeverity = severity === 'all' || investigation.risk.level === severity;
      return matchesQuery && matchesType && matchesStatus && matchesSeverity;
    });

    return filtered.sort((a, b) => {
      if (sortBy === 'risk-desc') return b.risk.score - a.risk.score;
      if (sortBy === 'indicator') return a.query.localeCompare(b.query);
      const dateDelta = new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime();
      return sortBy === 'date-asc' ? dateDelta : -dateDelta;
    });
  }, [historyList, query, severity, sortBy, status, type]);

  const selectedInvestigation =
    (selectedFull?.id === selectedId ? selectedFull : null) ??
    visibleHistory.find((investigation) => investigation.id === selectedId) ??
    visibleHistory[0] ??
    null;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Investigation history"
        subtitle="Search and compare persistent investigation records from SQLite database."
      >
        <DemoDataBadge label={isLiveBackend ? "SQLITE DATABASE" : "SAMPLE HISTORY"} />
      </PageHeader>

      <div
        role="note"
        className="rounded-lg border border-tn-border bg-tn-surface px-4 py-3 text-xs leading-5 text-tn-muted flex items-center justify-between"
      >
        <span>
          {isLiveBackend
            ? `Connected to persistent SQLite database. Showing ${historyList.length} investigation records.`
            : 'History contains built-in demonstration records and local sessions.'}
        </span>
        <span className="font-mono text-[10px] text-tn-info">
          {historyList.length} Total Records
        </span>
      </div>

      <section className="rounded-xl border border-tn-border bg-tn-surface p-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(200px,1.5fr)_repeat(4,minmax(130px,1fr))]">
          <label className="relative block">
            <span className="sr-only">Search history</span>
            <Search size={15} aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-tn-muted" />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search indicators or IDs"
              className="h-10 w-full rounded-lg border border-tn-border bg-tn-card pl-9 pr-3 text-xs text-tn-text placeholder:text-tn-muted focus:outline-none"
            />
          </label>
          <label className="flex items-center justify-between gap-2 text-[11px] text-tn-muted">
            Type
            <select
              value={type}
              onChange={(event) => setType(event.target.value as 'all' | IndicatorType)}
              className="h-10 min-w-28 rounded-lg border border-tn-border bg-tn-card px-2 text-xs text-tn-text"
            >
              <option value="all">All types</option>
              {indicatorTypes.map((item) => (
                <option key={item.value} value={item.value}>{item.label}</option>
              ))}
            </select>
          </label>
          <label className="flex items-center justify-between gap-2 text-[11px] text-tn-muted">
            Status
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value as 'all' | Investigation['status'])}
              className="h-10 min-w-28 rounded-lg border border-tn-border bg-tn-card px-2 text-xs text-tn-text"
            >
              <option value="all">All statuses</option>
              <option value="complete">Complete</option>
              <option value="scanning">Scanning</option>
              <option value="error">Error</option>
            </select>
          </label>
          <label className="flex items-center justify-between gap-2 text-[11px] text-tn-muted">
            Severity
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value as 'all' | Severity)}
              className="h-10 min-w-28 rounded-lg border border-tn-border bg-tn-card px-2 text-xs text-tn-text"
            >
              <option value="all">All levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Informational</option>
            </select>
          </label>
          <label className="flex items-center justify-between gap-2 text-[11px] text-tn-muted">
            Sort
            <select
              value={sortBy}
              onChange={(event) => setSortBy(event.target.value as SortBy)}
              className="h-10 min-w-32 rounded-lg border border-tn-border bg-tn-card px-2 text-xs text-tn-text"
            >
              <option value="date-desc">Newest first</option>
              <option value="date-asc">Oldest first</option>
              <option value="risk-desc">Highest risk</option>
              <option value="indicator">Indicator A–Z</option>
            </select>
          </label>
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-tn-border bg-tn-surface">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left">
            <thead className="bg-tn-card/60">
              <tr className="text-[10px] uppercase tracking-wide text-tn-muted">
                <th scope="col" className="px-4 py-3">Indicator</th>
                <th scope="col" className="px-3 py-3">Type</th>
                <th scope="col" className="px-3 py-3">Date (UTC)</th>
                <th scope="col" className="px-3 py-3">Status</th>
                <th scope="col" className="px-3 py-3">Risk score</th>
                <th scope="col" className="px-3 py-3">Severity</th>
                <th scope="col" className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-tn-border/70">
              {visibleHistory.map((investigation) => {
                const isSelected = selectedInvestigation?.id === investigation.id;
                return (
                  <tr
                    key={investigation.id}
                    onClick={() => setSelectedId(investigation.id)}
                    className={`text-xs transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-tn-card/75 border-l-2 border-l-tn-info'
                        : 'hover:bg-tn-card/30'
                    }`}
                  >
                    <td className="max-w-60 truncate px-4 py-3.5 font-mono text-tn-text">
                      {investigation.query}
                    </td>
                    <td className="px-3 py-3.5 text-tn-muted">{indicatorTypeLabel(investigation.type)}</td>
                    <td className="px-3 py-3.5 text-tn-muted">{formatDate(investigation.startedAt)}</td>
                    <td className="px-3 py-3.5">
                      <span className="rounded border border-tn-border bg-tn-card px-2 py-1 capitalize text-[10px] text-tn-muted">
                        {investigation.status}
                      </span>
                    </td>
                    <td className="px-3 py-3.5 font-medium text-tn-text">
                      {investigation.risk.score}/100
                    </td>
                    <td className="px-3 py-3.5">
                      <SeverityBadge severity={investigation.risk.level} />
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedId(investigation.id);
                        }}
                        aria-label={`View details for ${investigation.query}`}
                        aria-pressed={isSelected}
                        className={`rounded-md border px-2.5 py-1.5 text-[10px] font-medium transition-colors ${
                          isSelected
                            ? 'border-tn-info/60 bg-tn-card text-tn-info font-semibold'
                            : 'border-tn-border bg-tn-card text-tn-text hover:border-tn-muted'
                        }`}
                      >
                        View details
                      </button>
                    </td>
                  </tr>
                );
              })}
              {visibleHistory.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-2">
                    <EmptyState
                      icon={Search}
                      title="No matching history"
                      message="Try changing the search term or filters."
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="border-t border-tn-border px-4 py-3 text-[11px] text-tn-muted">
          {visibleHistory.length} sample {visibleHistory.length === 1 ? 'record' : 'records'}
        </div>
      </section>

      {selectedInvestigation ? (
        <InvestigationDetails investigation={selectedInvestigation} />
      ) : (
        <section className="rounded-xl border border-tn-border bg-tn-surface">
          <EmptyState
            icon={FileSearch}
            title="No record selected"
            message="Choose a sample history record to see its details."
          />
        </section>
      )}
    </div>
  );
}
