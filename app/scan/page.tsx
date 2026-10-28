'use client';

import { Suspense, useEffect, useState, useRef, useMemo } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  CheckCircle2,
  ChevronRight,
  Circle,
  Clock,
  Globe2,
  Hash,
  Loader2,
  Mail,
  Network,
  Search,
  Shield,
  Terminal,
  User,
  X,
} from 'lucide-react';
import { detectIndicatorType, indicatorTypeLabel } from '@/lib/indicators';
import { getAnalyst, saveInvestigation } from '@/lib/storage';
import { createInvestigation } from '@/lib/api';
import type { IndicatorType } from '@/lib/types';

// The 6 scanning stages required by the specification
interface ScanningStage {
  id: number;
  name: string;
  category: string;
  description: string;
  tag: string;
}

const SCANNING_STAGES: ScanningStage[] = [
  {
    id: 1,
    name: 'Input Validation',
    category: 'RFC & Protocol Syntax',
    description: 'Verifying indicator format, boundary constraints, and character encoding.',
    tag: 'INPUT_VAL',
  },
  {
    id: 2,
    name: 'Threat Reputation Lookup',
    category: 'Intelligence Feeds',
    description: 'Cross-referencing global malicious lists, C2 databases, and known threat actor feeds.',
    tag: 'REP_LOOKUP',
  },
  {
    id: 3,
    name: 'DNS, WHOIS and TLS Intelligence',
    category: 'Reconnaissance & Routing',
    description: 'Resolving passive DNS history, registrar ownership telemetry, and SSL/TLS certificates.',
    tag: 'NET_INTEL',
  },
  {
    id: 4,
    name: 'Indicator Relationship Analysis',
    category: 'Entity Correlation Graph',
    description: 'Building multi-hop topology, mapping associated IPs, child URLs, and parent infrastructure.',
    tag: 'GRAPH_REL',
  },
  {
    id: 5,
    name: 'Risk Assessment',
    category: 'Heuristic Scoring',
    description: 'Evaluating multi-vector confidence factors and calculating threat probability score.',
    tag: 'RISK_EVAL',
  },
  {
    id: 6,
    name: 'Report Generation',
    category: 'Forensic Synthesis',
    description: 'Compiling structured findings, mitigation playbooks, and executive intelligence brief.',
    tag: 'REPORT_GEN',
  },
];

interface LogEntry {
  timestamp: string;
  tag: string;
  message: string;
  level: 'info' | 'warn' | 'success';
}

function ScanningCore() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Read target and type from query parameters or fallback to demonstration indicator
  const rawTarget = searchParams.get('indicator') || searchParams.get('q') || '';
  const rawType = searchParams.get('type') || '';

  const target = useMemo(() => {
    return rawTarget.trim() || 'dark-stealer-c2.net';
  }, [rawTarget]);

  const detectedType = useMemo<IndicatorType>(() => {
    if (rawType && ['ip', 'domain', 'url', 'hash', 'email', 'username'].includes(rawType)) {
      return rawType as IndicatorType;
    }
    return detectIndicatorType(target) || 'domain';
  }, [rawType, target]);

  const [analystName, setAnalystName] = useState<string>('Agent Vanguard');
  const [progress, setProgress] = useState<number>(0);
  const [logs, setLogs] = useState<LogEntry[]>(() => {
    const timeStr = new Date().toTimeString().slice(0, 8);
    const initialTarget = rawTarget.trim() || 'dark-stealer-c2.net';
    return [
      {
        timestamp: timeStr,
        tag: 'INITIALIZE',
        message: `ThreatNova AI Autonomous Recon Engine initialized for [${initialTarget}]`,
        level: 'info',
      },
      {
        timestamp: timeStr,
        tag: 'TARGET_LOCK',
        message: `Indicator classified · Routing to 6-stage analysis pipeline`,
        level: 'info',
      },
    ];
  });
  const terminalRef = useRef<HTMLDivElement>(null);
  const redirectedRef = useRef<boolean>(false);

  // Load active analyst
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const activeAnalyst = getAnalyst();
      if (activeAnalyst?.name) {
        setAnalystName(activeAnalyst.name);
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  // Trigger backend investigation in parallel with the scanning animation
  useEffect(() => {
    let isCancelled = false;
    createInvestigation(target, detectedType)
      .then((backendInv) => {
        if (!isCancelled && backendInv) {
          saveInvestigation(backendInv);
        }
      })
      .catch((err) => {
        // Graceful fallback if backend is offline or indicator is demonstration-only
        console.debug('ThreatNova backend offline or mock mode:', err);
      });
    return () => {
      isCancelled = true;
    };
  }, [target, detectedType]);

  // Determine current active stage index (0 to 5)
  // Stage 1: 0 - 16%
  // Stage 2: 17 - 33%
  // Stage 3: 34 - 50%
  // Stage 4: 51 - 67%
  // Stage 5: 68 - 84%
  // Stage 6: 85 - 100%
  const currentStageIndex = useMemo(() => {
    if (progress < 17) return 0;
    if (progress < 34) return 1;
    if (progress < 51) return 2;
    if (progress < 68) return 3;
    if (progress < 85) return 4;
    return 5;
  }, [progress]);

  const isComplete = progress >= 100;

  // Main scanning animation timer: ~4 seconds from 0 to 100%
  useEffect(() => {
    let currentPercent = 0;
    const startTime = Date.now();
    const duration = 4000; // 4 seconds total
    let redirectTimer: number | null = null;

    // Stage milestones to push specific logs
    const loggedMilestones = new Set<number>();

    const interval = window.setInterval(() => {
      const elapsed = Date.now() - startTime;
      currentPercent = Math.min(100, Math.round((elapsed / duration) * 100));
      setProgress(currentPercent);

      const now = new Date();
      const timeStr = now.toTimeString().slice(0, 8);

      if (currentPercent >= 10 && !loggedMilestones.has(1)) {
        loggedMilestones.add(1);
        setLogs((prev) => [
          ...prev,
          {
            timestamp: timeStr,
            tag: 'INPUT_VAL',
            message: `Syntax validation passed. Canonical formatting established for ${target}.`,
            level: 'info',
          },
        ]);
      } else if (currentPercent >= 28 && !loggedMilestones.has(2)) {
        loggedMilestones.add(2);
        setLogs((prev) => [
          ...prev,
          {
            timestamp: timeStr,
            tag: 'REP_LOOKUP',
            message: `Correlating with ThreatNova feed fixtures. Matched 3 active C2 malicious campaigns.`,
            level: 'warn',
          },
        ]);
      } else if (currentPercent >= 46 && !loggedMilestones.has(3)) {
        loggedMilestones.add(3);
        setLogs((prev) => [
          ...prev,
          {
            timestamp: timeStr,
            tag: 'NET_INTEL',
            message: `Passive DNS: 4 historical IP resolutions. ASN prefix AS13335. Self-signed TLS flag noted.`,
            level: 'info',
          },
        ]);
      } else if (currentPercent >= 63 && !loggedMilestones.has(4)) {
        loggedMilestones.add(4);
        setLogs((prev) => [
          ...prev,
          {
            timestamp: timeStr,
            tag: 'GRAPH_REL',
            message: `Entity relationship graph synthesized: 8 related entity nodes, 12 infrastructure edges.`,
            level: 'info',
          },
        ]);
      } else if (currentPercent >= 80 && !loggedMilestones.has(5)) {
        loggedMilestones.add(5);
        setLogs((prev) => [
          ...prev,
          {
            timestamp: timeStr,
            tag: 'RISK_EVAL',
            message: `Risk scoring computed: 78/100 (HIGH RISK) with 85% statistical confidence.`,
            level: 'warn',
          },
        ]);
      } else if (currentPercent >= 98 && !loggedMilestones.has(6)) {
        loggedMilestones.add(6);
        setLogs((prev) => [
          ...prev,
          {
            timestamp: timeStr,
            tag: 'REPORT_GEN',
            message: `Intelligence summary packaged. Evidence chain verified. Ready for analyst review.`,
            level: 'success',
          },
        ]);
      }

      if (currentPercent >= 100) {
        window.clearInterval(interval);
        if (!redirectedRef.current) {
          redirectedRef.current = true;
          redirectTimer = window.setTimeout(() => {
            router.push(`/dashboard?q=${encodeURIComponent(target)}&completed=1`);
          }, 750);
        }
      }
    }, 45);

    return () => {
      window.clearInterval(interval);
      if (redirectTimer !== null) {
        window.clearTimeout(redirectTimer);
      }
    };
  }, [target, router]);

  // Auto-scroll terminal on new log entries
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  // Instant skip action
  const handleSkip = () => {
    redirectedRef.current = true;
    router.push(`/dashboard?q=${encodeURIComponent(target)}&completed=1`);
  };

  const getTypeIcon = (type: IndicatorType) => {
    switch (type) {
      case 'ip':
        return <Network size={13} className="text-[#EF4444]" />;
      case 'domain':
        return <Globe2 size={13} className="text-[#F2F2F2]" />;
      case 'url':
        return <Globe2 size={13} className="text-[#D4D4D4]" />;
      case 'hash':
        return <Hash size={13} className="text-[#EF4444]" />;
      case 'email':
        return <Mail size={13} className="text-[#8E8E8E]" />;
      case 'username':
        return <User size={13} className="text-[#F2F2F2]" />;
      default:
        return <Search size={13} className="text-[#8E8E8E]" />;
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#080808] text-[#F2F2F2] flex flex-col justify-between relative overflow-x-hidden font-sans select-none">
      {/* ── Background Layer 1: Ambient Red Radial Glow ── */}
      <div
        className="pointer-events-none absolute inset-0 z-0"
        style={{
          background:
            'radial-gradient(ellipse 70% 55% at 50% 42%, rgba(239, 68, 68, 0.08), transparent 75%)',
        }}
      />

      {/* ── Background Layer 2: Subtle Tactical Grid ── */}
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.05]"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(41, 41, 41, 0.4) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(41, 41, 41, 0.4) 1px, transparent 1px)
          `,
          backgroundSize: '44px 44px',
        }}
      />

      {/* ── Background Layer 3: Horizon Top Border Line ── */}
      <div className="pointer-events-none absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[#EF4444]/30 to-transparent" />

      {/* ── TOP BAR: Header ── */}
      <header className="relative z-20 w-full max-w-7xl mx-auto px-4 sm:px-6 py-4 sm:py-5 flex items-center justify-between">
        {/* Brand Lockup */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#171717] border border-[#292929] flex items-center justify-center shadow-[0_0_12px_rgba(239,68,68,0.2)]">
            <Shield size={16} className="text-[#EF4444]" />
          </div>
          <div>
            <span className="text-xs sm:text-sm font-mono tracking-[0.3em] font-bold text-[#F2F2F2] uppercase">
              THREATNOVA AI
            </span>
          </div>
        </div>

        {/* Status Pill */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full border border-[#EF4444]/25 bg-[#171717]/80 backdrop-blur-md">
          <span className="w-2 h-2 rounded-full bg-[#EF4444] animate-pulse shadow-[0_0_8px_rgba(239,68,68,0.9)]" />
          <span className="text-[11px] font-mono tracking-wider text-[#EF4444] uppercase">
            {isComplete ? 'PIPELINE COMPLETE' : 'SCAN PROTOCOL ACTIVE'}
          </span>
        </div>

        {/* Right Corner: Analyst & Abort / Return */}
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-md border border-[#292929] bg-[#171717]/70 text-[11px] font-mono text-[#8E8E8E]">
            <span className="text-[#8E8E8E]">OPERATOR:</span>
            <span className="text-[#F2F2F2] font-semibold">{analystName}</span>
          </div>

          <Link
            href="/investigate"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#292929] bg-[#171717]/80 hover:border-[#292929] hover:text-[#F2F2F2] text-[#8E8E8E] text-xs font-mono transition-colors"
            title="Cancel scan and return to investigation input"
          >
            <X size={13} />
            <span className="hidden sm:inline">Abort</span>
          </Link>
        </div>
      </header>

      {/* ── CENTER MAIN CONTENT ── */}
      <main className="relative z-10 w-full max-w-4xl mx-auto px-4 sm:px-6 py-6 sm:py-8 flex-1 flex flex-col items-center justify-center">
        {/* ── 1. CENTERED GLOBE / RADAR SCANNING VISUAL ── */}
        <div className="relative flex items-center justify-center mb-6 sm:mb-8">
          {/* Outer Pulsing Radar Waves */}
          <div className="absolute w-44 h-44 sm:w-56 sm:h-56 rounded-full border border-[#EF4444]/15 animate-ping opacity-25 pointer-events-none" />
          <div className="absolute w-36 h-36 sm:w-48 sm:h-48 rounded-full border border-[#EF4444]/20 animate-pulse pointer-events-none" />

          {/* Rotating Compass / Radar Reticle Ring */}
          <div className="absolute w-32 h-32 sm:w-40 sm:h-40 rounded-full border border-dashed border-[#292929] animate-[spin_24s_linear_infinite] pointer-events-none" />

          {/* Stylized Cyber Globe SVG */}
          <div className="relative w-28 h-28 sm:w-36 sm:h-36 rounded-full bg-[#171717] border border-[#292929] flex items-center justify-center shadow-[0_0_35px_rgba(239,68,68,0.2)]">
            <svg
              viewBox="0 0 100 100"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              className="w-24 h-24 sm:w-32 sm:h-32"
            >
              <defs>
                {/* Conical radar gradient */}
                <radialGradient id="radarSweep" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#EF4444" stopOpacity="0.4" />
                  <stop offset="80%" stopColor="#EF4444" stopOpacity="0.05" />
                  <stop offset="100%" stopColor="#EF4444" stopOpacity="0" />
                </radialGradient>
              </defs>

              {/* Globe Outer Circle */}
              <circle cx="50" cy="50" r="42" stroke="#292929" strokeWidth="1" />
              <circle cx="50" cy="50" r="32" stroke="#292929" strokeWidth="0.8" />
              <circle cx="50" cy="50" r="20" stroke="#292929" strokeWidth="0.6" strokeDasharray="2 3" />

              {/* Latitude Lines */}
              <ellipse cx="50" cy="50" rx="42" ry="16" stroke="#292929" strokeWidth="0.8" strokeDasharray="3 3" />
              <ellipse cx="50" cy="50" rx="42" ry="28" stroke="#292929" strokeWidth="0.7" />

              {/* Longitude Ellipse */}
              <ellipse cx="50" cy="50" rx="18" ry="42" stroke="#292929" strokeWidth="0.8" />

              {/* Equator and Prime Meridian axes */}
              <line x1="8" y1="50" x2="92" y2="50" stroke="#292929" strokeWidth="0.8" />
              <line x1="50" y1="8" x2="50" y2="92" stroke="#292929" strokeWidth="0.8" />

              {/* Rotating Radar Sweep Line */}
              <g className="origin-center animate-[spin_4s_linear_infinite]">
                <line x1="50" y1="50" x2="88" y2="22" stroke="#EF4444" strokeWidth="1.5" strokeLinecap="round" />
                <path d="M 50 50 L 88 22 A 42 42 0 0 0 60 9 Z" fill="url(#radarSweep)" opacity="0.6" />
              </g>

              {/* Pulsing Intercept Data Nodes on the globe */}
              <circle cx="36" cy="38" r="2" fill="#EF4444" className="animate-pulse" />
              <circle cx="64" cy="44" r="2.5" fill="#EF4444" className="animate-pulse" />
              <circle cx="48" cy="66" r="1.8" fill="#EF4444" className="animate-pulse" />
              <circle cx="72" cy="62" r="1.5" fill="#EF4444" />
              <circle cx="28" cy="58" r="1.5" fill="#EF4444" />

              {/* Central Core Reticle */}
              <circle cx="50" cy="50" r="4" fill="#080808" stroke="#EF4444" strokeWidth="1.5" />
              <circle cx="50" cy="50" r="1.5" fill="#EF4444" />
            </svg>
          </div>
        </div>

        {/* ── 2. TARGET DISPLAY ── */}
        <div className="w-full max-w-xl text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#292929] bg-[#171717]/90 text-[11px] font-mono uppercase tracking-widest text-[#8E8E8E] mb-2.5">
            {getTypeIcon(detectedType)}
            <span>TARGET: {indicatorTypeLabel(detectedType)}</span>
          </div>

          <h1 className="text-xl sm:text-2xl md:text-3xl font-mono font-bold text-[#F2F2F2] tracking-tight break-all">
            {target}
          </h1>

          <p className="text-xs sm:text-sm text-[#8E8E8E] mt-1.5 font-mono">
            {isComplete ? (
              <span className="text-[#EF4444] font-semibold flex items-center justify-center gap-1.5">
                <CheckCircle2 size={14} />
                Autonomous scanning completed · Redirecting to dashboard…
              </span>
            ) : (
              <span>Correlating global threat telemetry and infrastructure graph…</span>
            )}
          </p>
        </div>

        {/* ── 3. PROGRESS BAR & PERCENTAGE INDICATOR ── */}
        <div className="w-full max-w-2xl mt-6 sm:mt-7">
          <div className="flex items-center justify-between text-xs font-mono mb-2">
            <div className="flex items-center gap-2">
              <span className="text-[#8E8E8E]">STATUS:</span>
              <span className="text-[#F2F2F2] font-semibold">
                {isComplete
                  ? 'REPORT GENERATED'
                  : `STAGE ${currentStageIndex + 1}/6: ${SCANNING_STAGES[currentStageIndex]?.name.toUpperCase()}`}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs sm:text-sm font-bold text-[#EF4444] font-mono">
                {progress}%
              </span>
            </div>
          </div>

          {/* High-precision animated progress track */}
          <div
            className="w-full h-2 rounded-full bg-[#171717] border border-[#292929] overflow-hidden relative"
            role="progressbar"
            aria-valuenow={progress}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="ThreatNova AI Scanning Progress"
          >
            <div
              className="h-full rounded-full bg-gradient-to-r from-[#EF4444] via-[#DC2626] to-[#EF4444] transition-all duration-150 ease-out shadow-[0_0_15px_rgba(239,68,68,0.6)]"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* ── 4. THE 6 SCANNING STAGES CHECKLIST ── */}
        <div className="w-full max-w-2xl mt-6 sm:mt-8 grid grid-cols-1 sm:grid-cols-2 gap-2 sm:gap-2.5">
          {SCANNING_STAGES.map((stage, idx) => {
            const isFinished = idx < currentStageIndex || isComplete;
            const isCurrent = idx === currentStageIndex && !isComplete;

            return (
              <div
                key={stage.id}
                className={`p-3 rounded-lg border text-left transition-all duration-200 backdrop-blur-sm flex items-start gap-2.5 ${
                  isCurrent
                    ? 'border-[#EF4444]/80 bg-[#171717] shadow-[0_0_18px_rgba(239,68,68,0.15)] ring-1 ring-[#EF4444]/40'
                    : isFinished
                    ? 'border-[#292929] bg-[#171717]'
                    : 'border-[#292929]/40 bg-[#171717]/30 opacity-50'
                }`}
              >
                {/* Status Indicator Icon */}
                <div className="mt-0.5 shrink-0">
                  {isFinished ? (
                    <div className="w-5 h-5 rounded-full bg-[#292929] border border-[#292929] flex items-center justify-center shadow-[0_0_8px_rgba(239,68,68,0.2)]">
                      <CheckCircle2 size={13} className="text-[#F2F2F2] font-bold" />
                    </div>
                  ) : isCurrent ? (
                    <div className="w-5 h-5 rounded-full bg-[#171717] border border-[#EF4444] flex items-center justify-center shadow-[0_0_8px_rgba(239,68,68,0.4)]">
                      <Loader2 size={12} className="animate-spin text-[#EF4444]" />
                    </div>
                  ) : (
                    <div className="w-5 h-5 rounded-full bg-[#171717] border border-[#292929] flex items-center justify-center">
                      <Circle size={8} className="text-[#8E8E8E]" />
                    </div>
                  )}
                </div>

                {/* Stage Info */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-1.5">
                    <span
                      className={`text-xs font-mono font-semibold truncate ${
                        isCurrent
                          ? 'text-[#EF4444]'
                          : isFinished
                          ? 'text-[#F2F2F2]'
                          : 'text-[#8E8E8E]'
                      }`}
                    >
                      {stage.id}. {stage.name}
                    </span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase tracking-wider shrink-0 ${
                        isFinished
                          ? 'bg-[#292929] text-[#F2F2F2] border border-[#292929]'
                          : isCurrent
                          ? 'bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30 animate-pulse'
                          : 'bg-[#171717] text-[#8E8E8E] border border-[#292929]'
                      }`}
                    >
                      {isFinished ? 'Done' : isCurrent ? 'Active' : 'Queued'}
                    </span>
                  </div>
                  <p className="text-[10px] text-[#8E8E8E] leading-snug mt-0.5 line-clamp-1">
                    {stage.description}
                  </p>
                </div>
              </div>
            );
          })}
        </div>

        {/* ── 5. TERMINAL-STYLE SCANNING LOGS ── */}
        <div className="w-full max-w-2xl mt-6 rounded-xl border border-[#292929] bg-[#171717] overflow-hidden shadow-2xl">
          {/* Terminal Window Header */}
          <div className="flex items-center justify-between px-3.5 py-2 bg-[#171717] border-b border-[#292929] text-[11px] font-mono text-[#8E8E8E]">
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 mr-1">
                <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444] inline-block" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#292929] inline-block" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#8E8E8E] inline-block" />
              </div>
              <Terminal size={13} className="text-[#EF4444]" />
              <span className="font-semibold text-[#F2F2F2]">SCAN TELEMETRY LOGS</span>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-pulse" />
              <span className="text-[10px] text-[#EF4444]">STREAMING</span>
            </div>
          </div>

          {/* Terminal Log Output Window */}
          <div
            ref={terminalRef}
            className="p-3.5 font-mono text-[11px] leading-relaxed text-[#F2F2F2] max-h-36 sm:max-h-40 overflow-y-auto space-y-1 bg-[#080808]/70"
          >
            {logs.map((log, index) => (
              <div key={index} className="flex items-start gap-2">
                <span className="text-[#8E8E8E] shrink-0 select-none">[{log.timestamp}]</span>
                <span
                  className={`shrink-0 font-semibold text-[10px] px-1 py-0.2 rounded border ${
                    log.level === 'warn'
                      ? 'bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/30'
                      : log.level === 'success'
                      ? 'bg-[#292929] text-[#F2F2F2] border-[#292929]'
                      : 'bg-[#292929] text-[#8E8E8E] border-[#292929]'
                  }`}
                >
                  {log.tag}
                </span>
                <span
                  className={`break-all ${
                    index === logs.length - 1 ? 'text-[#F2F2F2] font-medium' : 'text-[#D4D4D4]'
                  }`}
                >
                  {log.message}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* ── 6. DEMO MODE BADGE & MANUAL SKIP BUTTON ── */}
        <div className="w-full max-w-2xl mt-5 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] font-mono text-[#8E8E8E]">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444]" />
            <span>DEMO MODE · LOCAL SYNTHETIC INTELLIGENCE PIPELINE</span>
          </div>

          <button
            type="button"
            onClick={handleSkip}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md border border-[#292929] bg-[#171717]/80 hover:border-[#EF4444] hover:text-[#EF4444] text-xs font-mono transition-colors cursor-pointer"
          >
            <span>Skip to Results</span>
            <ChevronRight size={13} />
          </button>
        </div>
      </main>

      {/* ── FOOTER ── */}
      <footer className="relative z-20 w-full max-w-6xl mx-auto px-6 py-4 border-t border-[#292929] flex flex-col sm:flex-row items-center justify-between gap-3 text-[10px] sm:text-[11px] font-mono tracking-widest text-[#8E8E8E] uppercase">
        <div className="flex items-center gap-2">
          <Clock size={12} className="text-[#8E8E8E]" />
          <span>REAL-TIME CORRELATION ENGINE</span>
        </div>

        <div className="text-[#8E8E8E] text-center">
          AUTONOMOUS THREAT INVESTIGATION PLATFORM · DEMONSTRATION WORKSPACE
        </div>

        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] shadow-[0_0_6px_rgba(239,68,68,0.8)]" />
          <span className="text-[#F2F2F2]">PIPELINE ACTIVE</span>
        </div>
      </footer>
    </div>
  );
}

export default function ScanningPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen w-full bg-[#080808] text-[#F2F2F2] flex items-center justify-center font-mono text-sm">
          <div className="flex items-center gap-2.5">
            <Loader2 size={16} className="animate-spin text-[#EF4444]" />
            <span>INITIALIZING SCAN CORE…</span>
          </div>
        </div>
      }
    >
      <ScanningCore />
    </Suspense>
  );
}
