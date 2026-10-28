'use client';

import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  Binary,
  GraduationCap,
  RotateCcw,
  Save,
  Server,
  Settings2,
  Shield,
} from 'lucide-react';
import DemoDataBadge from '@/components/DemoDataBadge';
import PageHeader from '@/components/PageHeader';
import { checkBackendHealth, type BackendHealth } from '@/lib/api';
import {
  getAnalyst,
  getInterfacePreferences,
  resetDemoData,
  setAnalyst,
  setInterfacePreferences,
} from '@/lib/storage';
import type { AnalystProfile, AnalystRole, InterfacePreferences } from '@/lib/types';

const ROLES: { role: AnalystRole; label: string; icon: typeof Shield }[] = [
  { role: 'Security Analyst', label: 'SOC & Triage', icon: Shield },
  { role: 'Threat Researcher', label: 'Intel & Attribution', icon: Binary },
  { role: 'Student Researcher', label: 'Academic & Lab', icon: GraduationCap },
];

const defaultPreferences: InterfacePreferences = {
  compactTables: false,
  reduceMotion: false,
};

const futureIntegrations = [
  {
    name: 'Python / FastAPI Backend',
    purpose: 'Autonomous investigation orchestrator & telemetry engine',
    state: 'Boundary Ready',
    target: 'http://localhost:8000/api/v1',
  },
  {
    name: 'SQLite Database',
    purpose: 'Local forensic history, session persistence & IOC indexing',
    state: 'Schema Designed',
    target: 'threatnova_intel.db',
  },
  {
    name: 'VirusTotal v3 API',
    purpose: 'Reputation lookups, sandbox executions, and detection ratios',
    state: 'Contract Prepared',
    target: 'Backend .env (VT_API_KEY)',
  },
  {
    name: 'LLM Reasoning Service',
    purpose: 'Autonomous threat synthesis & explainable risk factor breakdown',
    state: 'Contract Prepared',
    target: 'Backend .env (LLM_API_KEY)',
  },
];

export default function SettingsPanel() {
  const [analyst, setAnalystState] = useState<AnalystProfile | null>(null);
  const [preferences, setPreferences] = useState(defaultPreferences);
  const [name, setName] = useState('');
  const [role, setRole] = useState<AnalystRole>('Security Analyst');
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [confirmReset, setConfirmReset] = useState(false);
  const [backendHealth, setBackendHealth] = useState<BackendHealth | null>(null);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const profile = getAnalyst();
      setAnalystState(profile);
      setName(profile?.name ?? '');
      setRole(profile?.role ?? 'Security Analyst');
      setPreferences(getInterfacePreferences());
      setReady(true);
    });

    checkBackendHealth()
      .then((h) => setBackendHealth(h))
      .catch(() => setBackendHealth(null));

    return () => window.cancelAnimationFrame(frame);
  }, []);

  const integrationsList = useMemo(() => {
    if (!backendHealth) return futureIntegrations;
    return [
      {
        name: 'Python / FastAPI Backend',
        purpose: 'Autonomous investigation orchestrator & telemetry engine',
        state: `Online · v${backendHealth.version}`,
        stateColor: 'text-tn-success border-tn-success/30 bg-tn-success/10',
        target: 'http://localhost:8000',
      },
      {
        name: 'SQLite Database',
        purpose: 'Local forensic history, session persistence & IOC indexing',
        state: backendHealth.database === 'connected' ? 'Connected & Active' : 'Degraded',
        stateColor: backendHealth.database === 'connected' ? 'text-tn-success border-tn-success/30 bg-tn-success/10' : 'text-tn-warn border-tn-warn/30 bg-tn-warn/10',
        target: 'backend/threatnova.db',
      },
      {
        name: 'VirusTotal v3 API',
        purpose: 'Reputation lookups, sandbox executions, and detection ratios',
        state: backendHealth.virustotalConfigured ? 'Live API Active' : 'Demo Fixtures Active',
        stateColor: backendHealth.virustotalConfigured ? 'text-tn-success border-tn-success/30 bg-tn-success/10' : 'text-tn-warn border-tn-warn/30 bg-tn-warn/10',
        target: backendHealth.virustotalConfigured ? 'Live Telemetry' : 'Demo Mode (No Key)',
      },
      {
        name: 'LLM Reasoning Service',
        purpose: 'Autonomous threat synthesis & explainable risk factor breakdown',
        state: backendHealth.llmConfigured ? `${backendHealth.llmProvider} Active` : 'Heuristic Engine Active',
        stateColor: backendHealth.llmConfigured ? 'text-tn-success border-tn-success/30 bg-tn-success/10' : 'text-tn-info border-tn-info/30 bg-tn-info/10',
        target: backendHealth.llmConfigured ? `Provider: ${backendHealth.llmProvider}` : 'Autonomous Rule Engine',
      },
    ];
  }, [backendHealth]);

  useEffect(() => {
    if (!ready) return;
    document.documentElement.dataset.density = preferences.compactTables ? 'compact' : 'comfortable';
    document.documentElement.dataset.reduceMotion = preferences.reduceMotion ? 'true' : 'false';
  }, [preferences, ready]);

  function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) {
      setError('Please enter an analyst display name.');
      setMessage('');
      return;
    }
    if (trimmedName.length > 40) {
      setError('Display name must be 40 characters or fewer.');
      setMessage('');
      return;
    }

    try {
      const nextProfile: AnalystProfile = {
        name: trimmedName,
        role,
        avatarInitials: analyst?.avatarInitials || '🛡️',
        theme: 'dark',
      };
      setAnalyst(nextProfile);
      setAnalystState(nextProfile);
      setError('');
      setMessage('Analyst profile updated in local browser storage.');
    } catch {
      setError('The profile could not be saved. Check browser storage permissions.');
      setMessage('');
    }
  }

  function updatePreferences(nextPreferences: InterfacePreferences) {
    try {
      setInterfacePreferences(nextPreferences);
      setPreferences(nextPreferences);
      setError('');
      setMessage('Interface preferences updated in local browser storage.');
    } catch {
      setError('Preferences could not be saved. Check browser storage permissions.');
      setMessage('');
    }
  }

  function handleReset() {
    try {
      resetDemoData();
      setPreferences(defaultPreferences);
      setConfirmReset(false);
      setError('');
      setMessage('Local demo preferences were reset. Built-in sample datasets remain loaded.');
    } catch {
      setError('Saved demo data could not be reset. Check browser storage permissions.');
      setMessage('');
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Settings & Architecture"
        subtitle="Manage analyst identity, UI preferences, and review system integration boundaries."
      >
        <DemoDataBadge label="LOCAL SETTINGS" />
      </PageHeader>

      {(message || error) && (
        <div
          role={error ? 'alert' : 'status'}
          className={`rounded-xl border p-4 text-xs font-mono flex items-center justify-between ${
            error
              ? 'border-tn-danger/40 bg-tn-danger/10 text-tn-danger'
              : 'border-tn-success/40 bg-tn-success/10 text-tn-success'
          }`}
        >
          <span>{message || error}</span>
          <button
            type="button"
            onClick={() => {
              setMessage('');
              setError('');
            }}
            className="text-[10px] underline ml-2"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-2">
        {/* Analyst Profile Section */}
        <section className="rounded-xl border border-tn-border bg-tn-surface p-5 sm:p-6 shadow-md">
          <div className="flex items-center gap-3 border-b border-tn-border pb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-tn-border bg-tn-card">
              <Settings2 size={18} className="text-tn-info" aria-hidden="true" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-tn-text">Analyst Identity &amp; Role</h2>
              <p className="mt-0.5 text-xs text-tn-muted">Personalize investigator display and credentials persona</p>
            </div>
          </div>

          <form onSubmit={saveProfile} className="mt-5 space-y-4">
            <div>
              <label htmlFor="settings-name" className="mb-1.5 block text-xs font-medium text-tn-text">
                Investigator Alias / Display Name
              </label>
              <input
                id="settings-name"
                type="text"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  setError('');
                  setMessage('');
                }}
                maxLength={40}
                disabled={!ready}
                autoComplete="nickname"
                className="h-10 w-full rounded-lg border border-tn-border bg-tn-card px-3 text-sm text-tn-text focus:outline-none focus:border-tn-muted font-mono"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-xs font-medium text-tn-text">
                Investigator Role Persona
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {ROLES.map(({ role: r, label, icon: Icon }) => (
                  <button
                    key={r}
                    type="button"
                    onClick={() => setRole(r)}
                    className={`p-2.5 rounded-lg border text-left text-xs transition-all ${
                      role === r
                        ? 'border-tn-text bg-tn-card text-tn-text font-semibold'
                        : 'border-tn-border bg-tn-card/40 text-tn-muted hover:border-tn-muted'
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      <Icon size={13} className={role === r ? 'text-tn-info' : 'text-tn-muted'} />
                      <span className="truncate">{r.split(' ')[0]}</span>
                    </div>
                    <span className="text-[10px] text-tn-muted font-mono block mt-1">{label}</span>
                  </button>
                ))}
              </div>
            </div>

            <button
              type="submit"
              disabled={!ready}
              className="inline-flex items-center gap-2 rounded-lg border border-tn-muted/40 bg-tn-card px-4 py-2.5 text-xs font-semibold text-tn-text hover:bg-tn-border transition-colors cursor-pointer"
            >
              <Save size={14} aria-hidden="true" />
              Save Profile Changes
            </button>
          </form>
        </section>

        {/* Interface Preferences */}
        <section className="rounded-xl border border-tn-border bg-tn-surface p-5 sm:p-6 shadow-md">
          <div className="border-b border-tn-border pb-4">
            <h2 className="text-sm font-bold text-tn-text">Interface &amp; Display Preferences</h2>
            <p className="mt-0.5 text-xs text-tn-muted">Applied locally in this browser session</p>
          </div>

          <div className="mt-3 divide-y divide-tn-border/60">
            <label className="flex cursor-pointer items-start justify-between gap-4 py-3.5">
              <span>
                <span className="block text-xs font-semibold text-tn-text">Compact Density Mode</span>
                <span className="mt-1 block text-[11px] text-tn-muted leading-relaxed">
                  Reduces vertical padding across tables and data panels for higher investigative information density.
                </span>
              </span>
              <input
                type="checkbox"
                checked={preferences.compactTables}
                disabled={!ready}
                onChange={(e) =>
                  updatePreferences({ ...preferences, compactTables: e.target.checked })
                }
                className="mt-1 h-4 w-4 accent-[#EF4444]"
              />
            </label>

            <label className="flex cursor-pointer items-start justify-between gap-4 py-3.5">
              <span>
                <span className="block text-xs font-semibold text-tn-text">Reduced Motion</span>
                <span className="mt-1 block text-[11px] text-tn-muted leading-relaxed">
                  Minimizes transitions, pulse beacons, and D3 force simulation velocity for accessibility.
                </span>
              </span>
              <input
                type="checkbox"
                checked={preferences.reduceMotion}
                disabled={!ready}
                onChange={(e) =>
                  updatePreferences({ ...preferences, reduceMotion: e.target.checked })
                }
                className="mt-1 h-4 w-4 accent-[#EF4444]"
              />
            </label>
          </div>
        </section>

        {/* Backend Architecture Blueprint */}
        <section className="rounded-xl border border-tn-border bg-tn-surface p-5 sm:p-6 shadow-md xl:col-span-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-tn-border gap-2">
            <div>
              <h2 className="text-sm font-bold text-tn-text flex items-center gap-2">
                <Server size={16} className="text-tn-info" />
                Backend Architecture Blueprint &amp; Security Boundaries
              </h2>
              <p className="mt-0.5 text-xs text-tn-muted">
                Planned endpoints for Python FastAPI, SQLite, VirusTotal, and LLM services
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-tn-card border border-tn-border text-tn-muted">
              CLEAN BOUNDARY
            </span>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {integrationsList.map((item) => (
              <div
                key={item.name}
                className="rounded-lg border border-tn-border/70 bg-tn-card/40 p-3.5 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="text-xs font-bold text-tn-text">{item.name}</span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                        'stateColor' in item && item.stateColor
                          ? item.stateColor
                          : 'bg-tn-surface border-tn-border text-tn-info'
                      }`}
                    >
                      {item.state}
                    </span>
                  </div>
                  <p className="text-[11px] text-tn-muted leading-relaxed">{item.purpose}</p>
                </div>
                <div className="mt-3 pt-2 border-t border-tn-border/50 text-[10px] font-mono text-tn-text truncate">
                  Target: {item.target}
                </div>
              </div>
            ))}
          </div>

          {/* Security Notice regarding API keys */}
          <div className="mt-4 rounded-lg border border-tn-border/60 bg-tn-bg/60 p-3.5 flex items-start gap-3">
            <Shield size={16} className="mt-0.5 text-tn-success shrink-0" />
            <p className="text-xs text-tn-muted leading-relaxed">
              <strong className="text-tn-text font-semibold">Zero-Exposition Guarantee:</strong> API keys for VirusTotal and LLM reasoning services must never be hardcoded into frontend bundles. All outbound authenticated requests are routed exclusively through the Python / FastAPI backend proxy when connected.
            </p>
          </div>
        </section>

        {/* Application Information */}
        <section className="rounded-xl border border-tn-border bg-tn-surface p-5 sm:p-6 shadow-md">
          <div className="border-b border-tn-border pb-3">
            <h2 className="text-sm font-bold text-tn-text">Platform Metadata</h2>
            <p className="mt-0.5 text-xs text-tn-muted font-mono">
              ThreatNova AI v1.0.0-hackathon · HackIndia × KIT Hackathon 2026
            </p>
          </div>

          <dl className="mt-4 space-y-2 text-xs font-mono">
            <div className="flex justify-between py-1 border-b border-tn-border/40">
              <dt className="text-tn-muted">Frontend Framework:</dt>
              <dd className="text-tn-text">Next.js 16 (App Router + Turbopack)</dd>
            </div>
            <div className="flex justify-between py-1 border-b border-tn-border/40">
              <dt className="text-tn-muted">Graph Engine:</dt>
              <dd className="text-tn-text">D3.js Force Simulation v7</dd>
            </div>
            <div className="flex justify-between py-1 border-b border-tn-border/40">
              <dt className="text-tn-muted">Styling System:</dt>
              <dd className="text-tn-text">Tailwind CSS 4.0 (Custom Palettes)</dd>
            </div>
            <div className="flex justify-between py-1">
              <dt className="text-tn-muted">Target Hackathon:</dt>
              <dd className="text-tn-info font-bold">HackIndia × KIT Hackathon 2026</dd>
            </div>
          </dl>
        </section>

        {/* Reset Demo Data */}
        <section className="rounded-xl border border-tn-border bg-tn-surface p-5 sm:p-6 shadow-md flex flex-col justify-between">
          <div>
            <div className="border-b border-tn-border pb-3">
              <h2 className="text-sm font-bold text-tn-text">Reset Demonstration Workspace</h2>
              <p className="mt-0.5 text-xs text-tn-muted">
                Clear locally saved alert statuses and custom interface preferences
              </p>
            </div>
            <p className="mt-3 text-xs text-tn-muted leading-relaxed">
              This will clear non-sensitive browser storage entries (saved reviewed alert flags and density preferences) and restore factory demonstration states. Built-in sample datasets remain untouched.
            </p>
          </div>

          <div className="mt-5 pt-3 border-t border-tn-border">
            {confirmReset ? (
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleReset}
                  className="rounded-lg border border-tn-danger/40 bg-tn-danger/20 px-3 py-2 text-xs font-bold text-tn-danger hover:bg-tn-danger/30 transition-colors"
                >
                  Confirm Reset
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmReset(false)}
                  className="text-xs text-tn-muted hover:text-tn-text"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmReset(true)}
                className="inline-flex items-center gap-2 rounded-lg border border-tn-border bg-tn-card px-3.5 py-2 text-xs font-medium text-tn-muted hover:text-tn-text hover:border-tn-muted transition-colors cursor-pointer"
              >
                <RotateCcw size={14} />
                Reset Demo Preferences
              </button>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
