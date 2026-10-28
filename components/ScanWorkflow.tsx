'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ArrowLeft,
  Check,
  Circle,
  Clock3,
  FileSearch,
  LoaderCircle,
  Network,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from 'lucide-react';
import type { IndicatorType } from '@/lib/types';
import { indicatorTypeLabel } from '@/lib/indicators';
import { createInvestigation } from '@/lib/api';
import { saveInvestigation } from '@/lib/storage';

interface ScanStage {
  id: string;
  label: string;
  detail: string;
  module: string;
  logSample: string;
}

const STAGES: ScanStage[] = [
  {
    id: 'stage-val',
    label: '1. Validation',
    detail: 'Verifying indicator format, RFC syntax bounds, and protocol parameters locally.',
    module: 'Syntax Validation Module',
    logSample: 'Format verified. No malformed characters detected.',
  },
  {
    id: 'stage-rep',
    label: '2. Reputation Lookup',
    detail: 'Simulating cross-checks against threat intelligence feeds and VirusTotal fixtures.',
    module: 'Reputation Correlator',
    logSample: 'Correlated 3/7 threat feed fixtures: Known C2 infrastructure.',
  },
  {
    id: 'stage-net',
    label: '3. Domain & Network Intelligence',
    detail: 'Assembling simulated passive DNS, WHOIS registration, ASN routing, and TLS telemetry.',
    module: 'Network Recon Engine',
    logSample: 'DNS records gathered. ASN prefix resolved. Self-signed TLS flag noted.',
  },
  {
    id: 'stage-rel',
    label: '4. Relationship Analysis',
    detail: 'Building entity link graph, mapping associated IPs, child URLs, and parent infrastructure.',
    module: 'Graph Correlation Engine',
    logSample: 'Mapped 8 entity nodes and 12 link relationships in local cluster.',
  },
  {
    id: 'stage-evi',
    label: '5. Evidence Preparation',
    detail: 'Sequencing forensic evidence items, matching timestamps, and structuring provenance data.',
    module: 'Forensics Pipeline',
    logSample: 'Extracted 6 demonstration evidence items with source attribution.',
  },
  {
    id: 'stage-sum',
    label: '6. AI-Assisted Summary',
    detail: 'Synthesizing multi-source signals into an explainable risk score and contextual report.',
    module: 'AI Reasoning Engine',
    logSample: 'Risk score calculated at 78/100 (High Risk) with 85% confidence.',
  },
];

export default function ScanWorkflow({
  indicator,
  type,
}: {
  indicator: string;
  type: IndicatorType;
}) {
  const [completedStages, setCompletedStages] = useState(0);
  const [logs, setLogs] = useState<string[]>([
    `[${new Date().toISOString().slice(11, 19)}] [INIT] ThreatNova AI Scan Orchestrator v1.0.0 started`,
    `[${new Date().toISOString().slice(11, 19)}] [TARGET] Target: ${indicator} | Type: ${indicatorTypeLabel(type)}`,
  ]);

  const isComplete = completedStages >= STAGES.length;
  const progressPercent = Math.round((completedStages / STAGES.length) * 100);

  // Trigger persistent investigation in SQLite database in parallel with UI telemetry
  useEffect(() => {
    let isCancelled = false;
    createInvestigation(indicator, type)
      .then((savedInv) => {
        if (!isCancelled && savedInv) {
          saveInvestigation(savedInv);
        }
      })
      .catch((err) => {
        console.debug('Backend offline or simulated mode:', err);
      });
    return () => {
      isCancelled = true;
    };
  }, [indicator, type]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setCompletedStages((current) => {
        if (current >= STAGES.length) {
          window.clearInterval(timer);
          return current;
        }
        const next = current + 1;
        const stage = STAGES[current];
        if (stage) {
          setLogs((prev) => [
            ...prev,
            `[${new Date().toISOString().slice(11, 19)}] [${stage.module.toUpperCase()}] ${stage.label}: ${stage.logSample}`,
          ]);
        }
        if (next === STAGES.length) {
          setLogs((prev) => [
            ...prev,
            `[${new Date().toISOString().slice(11, 19)}] [COMPLETE] Simulated scanning finished. Investigation bundle ready.`,
          ]);
        }
        return next;
      });
    }, 750);

    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <Link
        href="/dashboard"
        className="inline-flex items-center gap-2 text-sm text-tn-muted hover:text-tn-text transition-colors"
      >
        <ArrowLeft size={15} aria-hidden="true" />
        Back to overview
      </Link>

      <section className="rounded-2xl border border-tn-border bg-tn-surface p-5 sm:p-7 shadow-xl">
        {/* Header */}
        <div className="flex flex-col gap-4 border-b border-tn-border pb-6 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3.5">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-tn-border bg-tn-card">
              {isComplete ? (
                <ShieldCheck size={24} className="text-tn-success" aria-hidden="true" />
              ) : (
                <LoaderCircle size={24} className="animate-spin text-tn-info" aria-hidden="true" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-tn-info">
                  Automated Pipeline
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-tn-warn/15 border border-tn-warn/30 text-tn-warn">
                  SIMULATED SCAN
                </span>
              </div>
              <h1 className="mt-1 text-2xl font-bold text-tn-text">
                {isComplete ? 'Threat Investigation Complete' : 'Executing Threat Investigation'}
              </h1>
              <p className="mt-1 text-xs text-tn-muted">
                {isComplete
                  ? 'All 6 investigative phases completed in local demonstration mode. No live telemetry was sent.'
                  : 'Synthesizing multi-source intelligence stages locally. Live outbound connections are disabled.'}
              </p>
            </div>
          </div>

          <div className="flex sm:flex-col items-end gap-1">
            <span className="text-xs text-tn-muted">Pipeline Status</span>
            <span
              className={`text-xs font-mono font-bold px-2.5 py-1 rounded-md border ${
                isComplete
                  ? 'bg-tn-success/15 border-tn-success/30 text-tn-success'
                  : 'bg-tn-card border-tn-border text-tn-info'
              }`}
            >
              {isComplete ? '100% COMPLETE' : `STAGE ${Math.min(completedStages + 1, 6)} OF 6`}
            </span>
          </div>
        </div>

        {/* Target Indicator Card */}
        <div className="mt-6 rounded-xl border border-tn-border bg-tn-bg/80 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-tn-muted block">
                Target Under Investigation
              </span>
              <div className="mt-1 flex items-center gap-2.5">
                <span className="rounded border border-tn-border bg-tn-card px-2.5 py-1 text-xs font-mono font-semibold text-tn-info">
                  {indicatorTypeLabel(type)}
                </span>
                <code className="font-mono text-sm sm:text-base font-semibold text-tn-text break-all">
                  {indicator}
                </code>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-tn-muted font-mono">
              <Clock3 size={13} />
              <span>Timestamp: {new Date().toLocaleTimeString()}</span>
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="py-6">
          <div className="mb-2 flex items-center justify-between text-xs">
            <span className="font-medium text-tn-text">Investigation Stage Progress</span>
            <span className="font-mono text-tn-info font-bold">{progressPercent}%</span>
          </div>
          <div
            className="h-2.5 overflow-hidden rounded-full bg-tn-card border border-tn-border"
            role="progressbar"
            aria-label="Simulated workflow progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progressPercent}
          >
            <div
              className="h-full rounded-full bg-tn-info transition-[width] duration-500 ease-out"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* 6 Investigation Stages Grid */}
        <div className="space-y-2.5" aria-label="Investigation stages">
          {STAGES.map((stage, index) => {
            const done = index < completedStages;
            const running = index === completedStages && !isComplete;

            return (
              <div
                key={stage.id}
                className={`flex items-start gap-3.5 rounded-xl border p-3.5 transition-all ${
                  running
                    ? 'border-tn-info/60 bg-tn-card/80 shadow-sm'
                    : done
                    ? 'border-tn-border/70 bg-tn-card/40'
                    : 'border-tn-border/40 bg-tn-card/20 opacity-60'
                }`}
              >
                <div className="mt-0.5 shrink-0">
                  {done ? (
                    <div className="w-5 h-5 rounded-full bg-tn-success/20 border border-tn-success/40 flex items-center justify-center">
                      <Check size={12} className="text-tn-success font-bold" />
                    </div>
                  ) : running ? (
                    <div className="w-5 h-5 rounded-full bg-tn-info/20 border border-tn-info/40 flex items-center justify-center">
                      <LoaderCircle size={12} className="animate-spin text-tn-info" />
                    </div>
                  ) : (
                    <div className="w-5 h-5 rounded-full bg-tn-card border border-tn-border flex items-center justify-center">
                      <Circle size={10} className="text-tn-muted" />
                    </div>
                  )}
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-tn-text">{stage.label}</p>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-tn-muted">
                      {stage.module}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-tn-muted leading-relaxed">{stage.detail}</p>
                </div>

                <span
                  className={`shrink-0 text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border ${
                    done
                      ? 'bg-tn-success/10 border-tn-success/30 text-tn-success'
                      : running
                      ? 'bg-tn-info/10 border-tn-info/30 text-tn-info'
                      : 'bg-tn-surface border-tn-border text-tn-muted'
                  }`}
                >
                  {done ? 'Complete' : running ? 'In Progress' : 'Queued'}
                </span>
              </div>
            );
          })}
        </div>

        {/* Live Simulation Terminal Console */}
        <div className="mt-6 rounded-xl border border-tn-border bg-tn-bg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-tn-surface border-b border-tn-border text-xs text-tn-muted font-mono">
            <div className="flex items-center gap-2">
              <Terminal size={14} className="text-tn-info" />
              <span>Simulated Telemetry Stream</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-tn-success animate-pulse" />
              <span className="text-[10px]">LIVE FEED</span>
            </div>
          </div>
          <div className="p-4 font-mono text-[11px] leading-relaxed text-tn-text space-y-1 max-h-44 overflow-y-auto bg-black/30">
            {logs.map((log, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className="text-tn-muted shrink-0">&gt;</span>
                <span className={i === logs.length - 1 ? 'text-tn-info font-medium' : 'text-tn-muted'}>
                  {log}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Demo Disclaimer Alert */}
        <div
          role="note"
          className="mt-6 flex items-start gap-3 rounded-xl border border-tn-warn/30 bg-tn-warn/10 p-3.5"
        >
          <ShieldAlert size={16} className="mt-0.5 shrink-0 text-tn-warn" aria-hidden="true" />
          <p className="text-xs leading-relaxed text-tn-muted">
            <strong className="text-tn-text">Simulated Demonstration:</strong> ThreatNova AI runs these scanning steps in demonstration mode to showcase system workflow and data structures. No live threat queries, network intrusions, or external API calls are executed.
          </p>
        </div>

        {/* Completion Action Bar */}
        {isComplete && (
          <div className="mt-6 pt-5 border-t border-tn-border">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-2.5 text-tn-success">
                <ShieldCheck size={20} />
                <span className="text-sm font-semibold">Investigation Bundle Ready for Review</span>
              </div>
              <div className="flex flex-wrap items-center gap-2.5 w-full sm:w-auto">
                <Link
                  href={`/dashboard?q=${encodeURIComponent(indicator)}&completed=1`}
                  className="flex-1 sm:flex-none inline-flex items-center justify-center gap-2 rounded-lg border border-tn-border bg-tn-card px-4 py-2.5 text-xs font-semibold text-tn-text hover:border-tn-muted transition-colors shadow-sm"
                >
                  <FileSearch size={14} />
                  Overview Dashboard
                </Link>
                <Link
                  href={`/graph?q=${encodeURIComponent(indicator)}`}
                  className="flex-1 sm:flex-none inline-flex items-center justify-center gap-2 rounded-lg border border-tn-border bg-tn-card px-4 py-2.5 text-xs font-semibold text-tn-info hover:border-tn-info transition-colors shadow-sm"
                >
                  <Network size={14} />
                  Threat Graph
                </Link>
                <Link
                  href="/findings"
                  className="flex-1 sm:flex-none inline-flex items-center justify-center gap-2 rounded-lg border border-tn-muted bg-tn-surface px-4 py-2.5 text-xs font-semibold text-tn-text hover:bg-tn-card transition-colors shadow-sm"
                >
                  <Zap size={14} className="text-tn-warn" />
                  View Findings
                </Link>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
