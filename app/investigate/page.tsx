'use client';

import { useEffect, useState, useRef, useMemo } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  AlertCircle,
  ArrowRight,
  ArrowUpRight,
  Check,
  Globe2,
  Hash,
  Layers,
  Lock,
  LogOut,
  Mail,
  Network,
  Search,
  Shield,
  User,
  X,
} from 'lucide-react';
import { getAnalyst, clearAnalyst, saveInvestigation } from '@/lib/storage';
import {
  detectIndicatorType,
  indicatorTypeLabel,
  isValidIndicator,
} from '@/lib/indicators';
import type { AnalystProfile, IndicatorType, Investigation } from '@/lib/types';

// Pre-configured demonstration indicators
const DEMO_EXAMPLES: {
  type: IndicatorType;
  value: string;
  label: string;
  category: string;
}[] = [
  {
    type: 'domain',
    value: 'dark-stealer-c2.net',
    label: 'dark-stealer-c2.net',
    category: 'Domain · Phishing C2',
  },
  {
    type: 'ip',
    value: '198.51.100.23',
    label: '198.51.100.23',
    category: 'IPv4 · Malicious Gateway',
  },
  {
    type: 'hash',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    label: 'e3b0c442...991b7852',
    category: 'SHA-256 · Dropper Sample',
  },
];

export default function MainInvestigationPage() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);

  const [analyst, setAnalyst] = useState<AnalystProfile | null>(null);
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [copiedExample, setCopiedExample] = useState<string | null>(null);
  const [displayedHeading, setDisplayedHeading] = useState('');

  // Typewriter effect for heading (70ms per char)
  useEffect(() => {
    const fullHeading = 'Every signal tells a story.';
    let index = 0;
    const timer = setInterval(() => {
      index++;
      setDisplayedHeading(fullHeading.slice(0, index));
      if (index >= fullHeading.length) {
        clearInterval(timer);
      }
    }, 70);

    return () => clearInterval(timer);
  }, []);

  // Derived indicator type via pure memoization
  const detectedType = useMemo(() => {
    const trimmed = query.trim();
    if (!trimmed) return null;
    return detectIndicatorType(trimmed);
  }, [query]);

  // Load active analyst identity
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const current = getAnalyst();
      if (current) {
        setAnalyst(current);
      } else {
        setAnalyst({
          name: 'Agent Vanguard',
          role: 'Security Analyst',
          avatarInitials: 'VG',
          theme: 'dark',
        });
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  const handleSelectExample = (example: (typeof DEMO_EXAMPLES)[0]) => {
    setQuery(example.value);
    setError(null);
    setCopiedExample(example.label);
    setTimeout(() => setCopiedExample(null), 1500);
    inputRef.current?.focus();
  };

  const handleClear = () => {
    setQuery('');
    setError(null);
    inputRef.current?.focus();
  };

  const handleSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const trimmed = query.trim();

    if (!trimmed) {
      setError(
        'Please enter an IP address, domain, URL, email, username, or file hash.',
      );
      inputRef.current?.focus();
      return;
    }

    const type = detectedType || detectIndicatorType(trimmed);

    if (!type || !isValidIndicator(trimmed, type)) {
      setError(
        'Unrecognized or invalid indicator format. Please enter a valid IPv4, domain, URL, email, username, or file hash.',
      );
      inputRef.current?.focus();
      return;
    }

    setIsSubmitting(true);
    setError(null);

    // Create local demonstration investigation record
    const newInvestigation: Investigation = {
      id: `inv-${Date.now().toString().slice(-4)}`,
      query: trimmed,
      type,
      status: 'scanning',
      startedAt: new Date().toISOString(),
      risk: {
        score: 78,
        level: 'high',
        confidence: 85,
        factors: [
          {
            name: 'Threat Intel Match',
            impact: 35,
            description: 'Matched demonstration threat intelligence fixtures',
          },
          {
            name: 'Network Anomaly',
            impact: 25,
            description: 'Demonstration DNS resolution and routing flags',
          },
          {
            name: 'Heuristic Scoring',
            impact: 18,
            description: 'Automated entity correlation heuristic assessment',
          },
        ],
        explanation:
          'Synthetic demonstration score generated for this local session. No live external intelligence APIs are queried without connected backend services.',
      },
      findings: [],
    };

    try {
      saveInvestigation(newInvestigation);
    } catch (err) {
      console.warn('Failed to save demo investigation', err);
    }

    // Navigate to the new scanning workflow
    const params = new URLSearchParams({
      indicator: trimmed,
      type,
    });

    setTimeout(() => {
      router.push(`/scan?${params.toString()}`);
    }, 200);
  };

  const handleExit = () => {
    clearAnalyst();
    router.push('/?switch=1');
  };

  const getTypeIcon = (type: IndicatorType) => {
    switch (type) {
      case 'ip':
        return <Network size={12} className="text-[#EF4444]" />;
      case 'domain':
        return <Globe2 size={12} className="text-[#F2F2F2]" />;
      case 'url':
        return <Globe2 size={12} className="text-[#D4D4D4]" />;
      case 'hash':
        return <Hash size={12} className="text-[#EF4444]" />;
      case 'email':
        return <Mail size={12} className="text-[#8E8E8E]" />;
      case 'username':
        return <User size={12} className="text-[#F2F2F2]" />;
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#080808] text-[#F2F2F2] flex flex-col justify-between relative overflow-x-hidden font-sans select-none">
      {/* ── Background Layer 1: Red illumination glow ── */}
      <div
        className="pointer-events-none absolute inset-0 z-0"
        style={{
          background:
            'radial-gradient(ellipse 65% 50% at 50% 46%, rgba(239, 68, 68, 0.08), transparent 75%)',
        }}
      />

      {/* ── Background Layer 2: Thin technical grid lines ── */}
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.06]"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(41, 41, 41, 0.4) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(41, 41, 41, 0.4) 1px, transparent 1px)
          `,
          backgroundSize: '48px 48px',
        }}
      />

      {/* ── Background Layer 3: Horizon Light Line ── */}
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

        {/* Right Corner: Analyst Identity & Quick Workspace Access */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Quick link to Overview Dashboard */}
          <Link
            href="/dashboard"
            className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#292929] bg-[#171717]/80 hover:border-[#292929] hover:bg-[#171717] text-xs font-mono text-[#8E8E8E] hover:text-[#F2F2F2] transition-all duration-200"
            title="Open Overview Workspace Dashboard"
          >
            <Layers size={13} className="text-[#8E8E8E]" />
            <span>Workspace</span>
            <ArrowUpRight size={12} className="text-[#8E8E8E]" />
          </Link>

          {/* Analyst Identity Card */}
          <div className="flex items-center gap-2 px-2.5 sm:px-3 py-1.5 rounded-lg border border-[#292929] bg-[#171717]/90 backdrop-blur-md">
            <div className="w-6 h-6 rounded bg-[#080808] border border-[#EF4444]/40 text-[#EF4444] text-[10px] font-mono font-bold flex items-center justify-center">
              {analyst?.avatarInitials || 'VG'}
            </div>
            <div className="hidden lg:flex flex-col text-left">
              <span className="text-xs font-mono font-semibold text-[#F2F2F2] leading-none">
                {analyst?.name || 'Agent Vanguard'}
              </span>
              <span className="text-[9px] font-mono text-[#8E8E8E] tracking-wider leading-none mt-0.5">
                {analyst?.role || 'Security Analyst'}
              </span>
            </div>
            {/* Status indicator */}
            <span
              className="w-1.5 h-1.5 rounded-full bg-[#EF4444] shadow-[0_0_6px_rgba(239,68,68,0.8)]"
              title="Session Active"
            />
          </div>

          {/* Switch Operator / Exit */}
          <button
            type="button"
            onClick={handleExit}
            className="p-2 rounded-lg border border-[#292929] bg-[#171717]/80 hover:border-[#292929] hover:text-[#F2F2F2] text-[#8E8E8E] text-xs transition-colors cursor-pointer"
            title="Switch Agent Profile / Exit"
          >
            <LogOut size={14} />
          </button>
        </div>
      </header>

      {/* ── CENTER MAIN CONTENT: Centered slightly above vertical center ── */}
      <main className="relative z-10 w-full max-w-4xl mx-auto px-4 sm:px-6 py-6 sm:py-10 flex-1 flex flex-col items-center justify-center -mt-6 sm:-mt-10 text-center">
        {/* Local Keyframes for text animations */}
        <style>{`
          @keyframes fadeInUp {
            from {
              opacity: 0;
              transform: translateY(12px);
              filter: blur(6px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
              filter: blur(0);
            }
          }
          @keyframes blinkBlock {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
          }
        `}</style>

        {/* Product Name & Subtitle */}
        <div className="flex flex-col items-center">
          <p
            className="text-[32px] md:text-[42px] lg:text-[48px] tracking-[0.20em] text-[#ff4d4d] font-mono font-extrabold uppercase flex justify-center text-center mb-2"
            style={{ textShadow: '0 0 18px rgba(255,77,77,0.9), 0 0 32px rgba(255,77,77,0.4)' }}
          >
            {'THREATNOVA AI'.split('').map((char, idx) => (
              <span
                key={idx}
                className="inline-block opacity-0"
                style={{
                  animation: 'fadeInUp 0.6s ease forwards',
                  animationDelay: `${idx * 80}ms`,
                }}
              >
                {char === ' ' ? '\u00A0' : char}
              </span>
            ))}
          </p>
          <p className="text-[10px] font-mono tracking-[0.15em] text-[#8E8E8E] opacity-80 uppercase max-w-[380px] mx-auto text-center mb-4 sm:mb-5">
            AUTONOMOUS THREAT INVESTIGATION SYSTEM
          </p>
        </div>

        {/* Prominent Heading */}
        <h1 className="text-5xl md:text-6xl font-bold text-white tracking-tight h-[70px] flex items-center justify-center">
          <span>{displayedHeading}</span>
          <span
            className="inline-block w-[0.45em] h-[0.85em] bg-white ml-1.5 align-baseline"
            style={{
              animation: 'blinkBlock 1s steps(2, start) infinite',
            }}
            aria-hidden="true"
          />
        </h1>

        {/* Supporting Text */}
        <p className="text-sm sm:text-base text-[#8E8E8E] font-normal mt-3.5 sm:mt-4 max-w-xl">
          Investigate indicators. Discover connections. Understand risk.
        </p>

        {/* ── CENTRAL INVESTIGATION SEARCH BAR ── */}
        <form
          onSubmit={handleSubmit}
          className="w-full max-w-2xl sm:max-w-3xl mt-8 sm:mt-10 relative flex flex-col items-center"
        >
          <div className="group w-full relative flex items-center bg-[#171717] border border-[#292929] hover:border-[#292929] focus-within:border-[#EF4444] focus-within:ring-4 focus-within:ring-[#EF4444]/15 shadow-[0_12px_40px_rgba(0,0,0,0.6),0_0_30px_rgba(239,68,68,0.1)] rounded-full p-2 pl-4 sm:pl-6 backdrop-blur-xl transition-all duration-300">
            {/* Search Icon */}
            <Search
              size={18}
              className="text-[#8E8E8E] group-focus-within:text-[#EF4444] transition-colors shrink-0 mr-3"
            />

            {/* Input field */}
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                if (error) setError(null);
              }}
              placeholder="Enter IP, domain, URL, email or username..."
              className="w-full bg-transparent text-sm sm:text-base font-mono text-[#F2F2F2] placeholder:text-[#8E8E8E]/60 outline-none pr-3"
              autoComplete="off"
              spellCheck="false"
              aria-label="Investigation Indicator Input"
            />

            {/* Real-time Detected Category Badge */}
            {detectedType && (
              <div className="hidden sm:flex items-center gap-1.5 mr-2 px-2.5 py-1 rounded-full border border-[#EF4444]/30 bg-[#EF4444]/10 text-[10px] font-mono uppercase tracking-wider text-[#EF4444] shrink-0">
                {getTypeIcon(detectedType)}
                <span>{indicatorTypeLabel(detectedType)}</span>
              </div>
            )}

            {/* Clear Button */}
            {query && (
              <button
                type="button"
                onClick={handleClear}
                className="p-1.5 text-[#8E8E8E] hover:text-[#F2F2F2] rounded-full hover:bg-[#292929] transition-colors mr-1.5 shrink-0 cursor-pointer"
                title="Clear input"
              >
                <X size={15} />
              </button>
            )}

            {/* Investigate Action Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="bg-gradient-to-r from-[#EF4444] to-[#DC2626] hover:from-[#DC2626] hover:to-[#B91C1C] text-[#F2F2F2] font-mono font-bold text-xs sm:text-sm tracking-wider uppercase px-5 sm:px-6 py-2.5 sm:py-3 rounded-full flex items-center gap-2 transition-all duration-200 shadow-[0_0_20px_rgba(239,68,68,0.35)] hover:shadow-[0_0_25px_rgba(239,68,68,0.5)] cursor-pointer shrink-0 disabled:opacity-60 group/btn"
            >
              {isSubmitting ? (
                <span>ROUTING…</span>
              ) : (
                <>
                  <span>INVESTIGATE</span>
                  <ArrowRight
                    size={16}
                    className="group-hover/btn:translate-x-1 transition-transform duration-200"
                  />
                </>
              )}
            </button>
          </div>

          {/* Validation & Error Message Display */}
          {error && (
            <div
              role="alert"
              className="mt-3.5 w-full max-w-2xl px-4 py-2.5 rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/15 text-[#EF4444] text-xs font-mono flex items-center gap-2.5 text-left backdrop-blur-md animate-in fade-in slide-in-from-top-1"
            >
              <AlertCircle size={15} className="shrink-0 text-[#EF4444]" />
              <span>{error}</span>
            </div>
          )}
        </form>

        {/* ── INTELLIGENCE CAPABILITIES LINE ── */}
        <div className="mt-5 w-full max-w-2xl flex flex-wrap items-center justify-center gap-x-2 sm:gap-x-2.5 gap-y-1 text-[10px] sm:text-[11px] font-mono tracking-widest text-[#8E8E8E] uppercase text-center">
          <span>THREAT INTELLIGENCE</span>
          <span className="text-[#EF4444]/40">·</span>
          <span>DNS &amp; WHOIS</span>
          <span className="text-[#EF4444]/40">·</span>
          <span>SSL/TLS</span>
          <span className="text-[#EF4444]/40">·</span>
          <span>INDICATOR CORRELATION</span>
          <span className="text-[#EF4444]/40">·</span>
          <span>RISK ANALYSIS</span>
        </div>

        {/* ── OPTIONAL QUICK EXAMPLES: Try a Demo Investigation ── */}
        <div className="mt-8 sm:mt-10 w-full max-w-2xl flex flex-col items-center">
          <p className="text-[10px] font-mono tracking-[0.22em] text-[#8E8E8E] uppercase font-semibold mb-3">
            TRY A DEMO INVESTIGATION
          </p>

          <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-2.5">
            {DEMO_EXAMPLES.map((example) => {
              const isSelected = query === example.value;
              return (
                <button
                  key={example.value}
                  type="button"
                  onClick={() => handleSelectExample(example)}
                  className={`px-3.5 py-2 rounded-lg border text-left transition-all duration-200 backdrop-blur-sm cursor-pointer flex items-center gap-2.5 ${
                    isSelected
                      ? 'border-[#EF4444]/80 bg-[#EF4444]/10 text-[#F2F2F2] shadow-[0_0_15px_rgba(239,68,68,0.2)]'
                      : 'border-[#292929] bg-[#171717]/80 hover:border-[#292929] hover:bg-[#171717] text-[#8E8E8E] hover:text-[#F2F2F2]'
                  }`}
                >
                  <div className="flex flex-col">
                    <span className="text-xs font-mono font-medium text-[#F2F2F2]">
                      {example.label}
                    </span>
                    <span className="text-[9px] font-mono text-[#8E8E8E] mt-0.5">
                      {example.category}
                    </span>
                  </div>
                  {copiedExample === example.label ? (
                    <Check size={13} className="text-[#EF4444] ml-1 shrink-0" />
                  ) : (
                    <span className="text-[10px] font-mono text-[#EF4444] ml-1 shrink-0">
                      →
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Disclaimer Notice */}
        <div className="mt-9 sm:mt-12 flex items-center gap-2 px-3 py-1.5 rounded-full border border-[#292929] bg-[#171717]/80 text-[10px] font-mono text-[#8E8E8E] tracking-wider">
          <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444]/80" />
          <span>
            DEMONSTRATION WORKSPACE · SYNTHETIC FIXTURES &amp; LOCAL CORRELATION ENGINE
          </span>
        </div>
      </main>

      {/* ── FOOTER: Node Status, Terms, Operational Disclaimer ── */}
      <footer className="relative z-20 w-full max-w-6xl mx-auto px-6 py-4 sm:py-5 border-t border-[#292929] flex flex-col sm:flex-row items-center justify-between gap-3 text-[10px] sm:text-[11px] font-mono tracking-widest text-[#8E8E8E] uppercase">
        <div className="flex items-center gap-2">
          <Lock size={12} className="text-[#8E8E8E]" />
          <span>SECURE RECONNAISSANCE CORE</span>
        </div>

        <div className="text-[#8E8E8E] text-center">
          NON-PRODUCTION ENVIRONMENT · CLIENT-SIDE WORKSPACE DEMONSTRATION
        </div>

        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] shadow-[0_0_6px_rgba(239,68,68,0.8)]" />
          <span className="text-[#F2F2F2]">SYSTEM READY</span>
        </div>
      </footer>
    </div>
  );
}
