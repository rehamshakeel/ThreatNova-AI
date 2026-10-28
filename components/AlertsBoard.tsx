'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  BellRing,
  ExternalLink,
  Search,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import DemoDataBadge from '@/components/DemoDataBadge';
import EmptyState from '@/components/EmptyState';
import PageHeader from '@/components/PageHeader';
import SeverityBadge from '@/components/SeverityBadge';
import { fetchAlerts } from '@/lib/api';
import { createDemoAlerts } from '@/lib/demo-data';
import { getAlerts, saveAlerts } from '@/lib/storage';
import type { Alert, Severity } from '@/lib/types';

type AlertStatusFilter = 'all' | 'new' | 'reviewed';

const sampleAlerts = createDemoAlerts();

function formatTimestamp(timestamp: string): string {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(timestamp));
}

export default function AlertsBoard() {
  const [alerts, setAlerts] = useState<Alert[]>(sampleAlerts);
  const [severity, setSeverity] = useState<'all' | Severity>('all');
  const [status, setStatus] = useState<AlertStatusFilter>('all');
  const [query, setQuery] = useState('');
  const [error, setError] = useState('');
  const [isLiveConnected, setIsLiveConnected] = useState<boolean>(false);

  useEffect(() => {
    let isMounted = true;

    fetchAlerts(severity === 'all' ? undefined : severity, 100)
      .then((liveAlerts) => {
        if (!isMounted) return;
        const savedAlerts = getAlerts();
        const base = liveAlerts.length > 0 ? liveAlerts : createDemoAlerts();
        const merged = base.map((alert) => {
          const saved = savedAlerts.find((item) => item.id === alert.id);
          return saved ? { ...alert, read: saved.read } : alert;
        });
        setAlerts(merged);
        setIsLiveConnected(liveAlerts.length > 0);
      })
      .catch((err) => {
        if (!isMounted) return;
        console.debug('Failed to fetch live alerts from SQLite, using demo fallback:', err);
        const savedAlerts = getAlerts();
        const fallback = createDemoAlerts().map((alert) => {
          const saved = savedAlerts.find((item) => item.id === alert.id);
          return saved ? { ...alert, read: saved.read } : alert;
        });
        setAlerts(fallback);
        setIsLiveConnected(false);
      });

    return () => {
      isMounted = false;
    };
  }, [severity]);

  const visibleAlerts = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return alerts.filter((alert) => {
      const matchesSeverity = severity === 'all' || alert.severity === severity;
      const matchesStatus =
        status === 'all' || (status === 'new' ? !alert.read : alert.read);
      const matchesQuery =
        !normalizedQuery ||
        alert.title.toLowerCase().includes(normalizedQuery) ||
        (alert.indicator ?? '').toLowerCase().includes(normalizedQuery) ||
        alert.message.toLowerCase().includes(normalizedQuery) ||
        alert.source.toLowerCase().includes(normalizedQuery);
      return matchesSeverity && matchesStatus && matchesQuery;
    });
  }, [alerts, query, severity, status]);

  function toggleReviewed(alert: Alert) {
    const updated = alerts.map((item) =>
      item.id === alert.id ? { ...item, read: !item.read } : item,
    );

    try {
      saveAlerts(updated);
      setAlerts(updated);
      setError('');
    } catch {
      setError('The alert status could not be saved in local storage. Check browser permissions.');
    }
  }

  const unreadCount = alerts.filter((a) => !a.read).length;
  const criticalCount = alerts.filter((a) => a.severity === 'critical' || a.severity === 'high').length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Alerts & Early-Warning Feed"
        subtitle="Operational triage queue for automated indicator alerts and anomalous signals."
      >
        {isLiveConnected ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-mono font-medium text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span> SQLITE PERSISTED ALERTS
          </span>
        ) : (
          <DemoDataBadge label="DEMO ALERTS" />
        )}
      </PageHeader>

      {/* Demonstration Boundary Notice */}
      <div
        role="note"
        className="rounded-xl border border-tn-border bg-tn-surface px-4 py-3 text-xs leading-relaxed text-tn-muted shadow-sm flex items-start gap-3"
      >
        <ShieldAlert size={16} className={`mt-0.5 shrink-0 ${isLiveConnected ? 'text-emerald-400' : 'text-tn-warn'}`} aria-hidden="true" />
        <p>
          {isLiveConnected ? (
            <>
              <strong className="text-tn-text">Live SQLite Alert Feed:</strong> Threat signals are dynamically extracted from high-severity findings and critical risk assessments persisted in SQLite. Triage state is stored in your browser session.
            </>
          ) : (
            <>
              <strong className="text-tn-text">Demonstration Feed:</strong> These alert records are static operational fixtures. No live telemetry listener or production SIEM ingestion is connected. Triage acknowledgment state is persisted locally in your browser storage.
            </>
          )}
        </p>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-tn-border bg-tn-surface p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-tn-muted block">
            Total Alerts
          </span>
          <p className="text-xl font-bold font-mono text-tn-text mt-1">{alerts.length}</p>
          <span className="text-[11px] text-tn-muted mt-0.5 block">Recorded in queue</span>
        </div>
        <div className="rounded-xl border border-tn-border bg-tn-surface p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-tn-danger block">
            High / Critical
          </span>
          <p className="text-xl font-bold font-mono text-tn-danger mt-1">{criticalCount}</p>
          <span className="text-[11px] text-tn-muted mt-0.5 block">Requires immediate triage</span>
        </div>
        <div className="rounded-xl border border-tn-border bg-tn-surface p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-tn-info block">
            Unreviewed Signals
          </span>
          <p className="text-xl font-bold font-mono text-tn-info mt-1">{unreadCount}</p>
          <span className="text-[11px] text-tn-muted mt-0.5 block">Pending analyst review</span>
        </div>
        <div className="rounded-xl border border-tn-border bg-tn-surface p-4">
          <span className="text-[10px] font-mono uppercase tracking-wider text-tn-success block">
            Reviewed
          </span>
          <p className="text-xl font-bold font-mono text-tn-success mt-1">{alerts.length - unreadCount}</p>
          <span className="text-[11px] text-tn-muted mt-0.5 block">Acknowledged in session</span>
        </div>
      </div>

      {/* Filters Toolbar */}
      <section className="rounded-xl border border-tn-border bg-tn-surface p-4 shadow-sm">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(220px,1.5fr)_repeat(2,minmax(170px,1fr))]">
          <label className="relative block">
            <span className="sr-only">Search alerts</span>
            <Search
              size={14}
              aria-hidden="true"
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-tn-muted"
            />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search alerts by title, indicator, source…"
              className="h-10 w-full rounded-lg border border-tn-border bg-tn-card pl-9 pr-3 text-xs text-tn-text placeholder:text-tn-muted/60 focus:outline-none focus:border-tn-muted font-mono"
            />
          </label>

          <label className="flex items-center justify-between gap-3 text-xs text-tn-muted">
            Severity
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as 'all' | Severity)}
              className="h-10 min-w-36 rounded-lg border border-tn-border bg-tn-card px-2.5 text-xs text-tn-text focus:outline-none focus:border-tn-muted"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Informational</option>
            </select>
          </label>

          <label className="flex items-center justify-between gap-3 text-xs text-tn-muted">
            Review Status
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as AlertStatusFilter)}
              className="h-10 min-w-36 rounded-lg border border-tn-border bg-tn-card px-2.5 text-xs text-tn-text focus:outline-none focus:border-tn-muted"
            >
              <option value="all">All Statuses</option>
              <option value="new">New (Unreviewed)</option>
              <option value="reviewed">Reviewed</option>
            </select>
          </label>
        </div>

        {error && (
          <p className="mt-3 text-xs text-tn-danger flex items-center gap-1" role="alert">
            <AlertTriangle size={13} /> {error}
          </p>
        )}
      </section>

      {/* Alert Cards Feed */}
      <section aria-label="Alert records" className="space-y-3.5">
        {visibleAlerts.map((alert) => (
          <article
            key={alert.id}
            className={`rounded-xl border transition-all p-5 shadow-sm ${
              alert.read
                ? 'border-tn-border/70 bg-tn-surface/60 opacity-80'
                : 'border-tn-border bg-tn-surface shadow-md'
            }`}
          >
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="flex min-w-0 flex-1 gap-3.5">
                <div
                  className={`mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${
                    alert.severity === 'critical' || alert.severity === 'high'
                      ? 'border-tn-danger/30 bg-tn-danger/10 text-tn-danger'
                      : 'border-tn-border bg-tn-card text-tn-muted'
                  }`}
                >
                  <BellRing size={18} aria-hidden="true" />
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h2 className="text-sm font-bold text-tn-text">{alert.title}</h2>
                    <SeverityBadge severity={alert.severity} />
                    <span
                      className={`rounded-md border px-2 py-0.5 text-[9px] font-mono font-semibold uppercase tracking-wider ${
                        alert.read
                          ? 'border-tn-border bg-tn-card text-tn-muted'
                          : 'border-tn-info/30 bg-tn-info/15 text-tn-info animate-pulse'
                      }`}
                    >
                      {alert.read ? 'Reviewed' : 'New Alert'}
                    </span>
                  </div>

                  <p className="mt-2 text-xs leading-relaxed text-tn-muted">{alert.message}</p>

                  <dl className="mt-3.5 grid gap-3 border-t border-tn-border/60 pt-3 sm:grid-cols-2 xl:grid-cols-4 font-mono text-xs">
                    <div>
                      <dt className="text-[9px] uppercase tracking-wider text-tn-muted">Indicator</dt>
                      <dd className="mt-0.5 break-all font-semibold text-tn-text">
                        {alert.indicator ?? 'N/A'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-[9px] uppercase tracking-wider text-tn-muted">Detection Source</dt>
                      <dd className="mt-0.5 text-tn-text">{alert.source}</dd>
                    </div>
                    <div>
                      <dt className="text-[9px] uppercase tracking-wider text-tn-muted">Timestamp (UTC)</dt>
                      <dd className="mt-0.5 text-tn-text">{formatTimestamp(alert.timestamp)}</dd>
                    </div>
                    <div>
                      <dt className="text-[9px] uppercase tracking-wider text-tn-muted">Linked Record</dt>
                      <dd className="mt-0.5">
                        {alert.investigationId ? (
                          <Link
                            href={`/history?investigation=${encodeURIComponent(alert.investigationId)}`}
                            className="text-tn-info hover:underline inline-flex items-center gap-1"
                          >
                            <span>{alert.investigationId}</span>
                            <ExternalLink size={10} />
                          </Link>
                        ) : (
                          <span className="text-tn-muted">Independent Signal</span>
                        )}
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-tn-border/50">
                {alert.indicator && (
                  <Link
                    href={`/scanning?type=domain&indicator=${encodeURIComponent(alert.indicator)}`}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-tn-border bg-tn-card px-3 py-2 text-xs font-semibold text-tn-info hover:border-tn-muted transition-colors cursor-pointer"
                  >
                    <Zap size={13} className="text-tn-warn" />
                    Investigate
                  </Link>
                )}
                <button
                  type="button"
                  onClick={() => toggleReviewed(alert)}
                  aria-pressed={alert.read}
                  className="rounded-lg border border-tn-border bg-tn-card px-3 py-2 text-xs font-medium text-tn-text hover:border-tn-muted transition-colors cursor-pointer"
                >
                  Mark as {alert.read ? 'New' : 'Reviewed'}
                </button>
              </div>
            </div>
          </article>
        ))}

        {visibleAlerts.length === 0 && (
          <section className="rounded-xl border border-tn-border bg-tn-surface p-10">
            <EmptyState
              icon={BellRing}
              title="No matching alerts"
              message="Adjust search query, severity, or review status filter."
            />
          </section>
        )}
      </section>

      <div className="text-[11px] font-mono text-tn-muted flex items-center justify-between border-t border-tn-border/60 pt-3">
        <span>Showing {visibleAlerts.length} of {alerts.length} operational alerts</span>
        <span>ThreatNova AI Triage Queue</span>
      </div>
    </div>
  );
}
