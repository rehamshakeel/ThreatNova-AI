'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Lock } from 'lucide-react';
import { getAnalyst, setAnalyst } from '@/lib/storage';
import type { AnalystRole } from '@/lib/types';

interface AgentCard {
  id: string;
  callsign: string;
  designation: string;
  role: AnalystRole;
  monogram: string;
  defaultName: string;
  shieldIcon: (isSelected: boolean) => React.ReactNode;
}

const AGENTS: AgentCard[] = [
  {
    id: 'agent-1',
    callsign: 'VANGUARD-01',
    designation: 'TACTICAL',
    role: 'Security Analyst',
    monogram: 'VG',
    defaultName: 'Agent Vanguard',
    shieldIcon: (isSelected) => (
      <svg
        viewBox="0 0 72 88"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-14 h-16 sm:w-16 sm:h-20 transition-all duration-300"
      >
        {/* Tactical Faceted Shield */}
        <path
          d="M36 6 L64 18 L64 52 C64 68 50 78 36 82 C22 78 8 68 8 52 L8 18 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.75"
          fill={isSelected ? '#1F1414' : '#171717'}
        />
        {/* Inner Armor Ridge */}
        <path
          d="M36 14 L56 24 L56 50 C56 62 46 70 36 74 C26 70 16 62 16 50 L16 24 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.2"
          fill={isSelected ? '#281414' : '#141414'}
          fillOpacity={isSelected ? '0.7' : '0.4'}
        />
        {/* Tactical Central Sensor Slit */}
        <line
          x1="36"
          y1="22"
          x2="36"
          y2="60"
          stroke={isSelected ? '#F2F2F2' : '#8E8E8E'}
          strokeWidth="2"
          strokeLinecap="round"
        />
        {/* Horizontal Laser Tick */}
        <line
          x1="26"
          y1="40"
          x2="46"
          y2="40"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.5"
        />
        <circle cx="36" cy="40" r="3" fill={isSelected ? '#EF4444' : '#292929'} />
        <circle cx="36" cy="40" r="1.5" fill="#F2F2F2" />
      </svg>
    ),
  },
  {
    id: 'agent-2',
    callsign: 'SPECTRE-02',
    designation: 'RECON',
    role: 'Threat Researcher',
    monogram: 'SP',
    defaultName: 'Agent Spectre',
    shieldIcon: (isSelected) => (
      <svg
        viewBox="0 0 72 88"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-14 h-16 sm:w-16 sm:h-20 transition-all duration-300"
      >
        {/* Stealth Recon Shield */}
        <path
          d="M36 6 L66 20 L60 56 C60 69 48 78 36 82 C24 78 12 69 12 56 L6 20 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.75"
          fill={isSelected ? '#1F1414' : '#171717'}
        />
        {/* Stealth Wing Contours */}
        <path
          d="M36 16 L54 26 L50 52 C50 62 42 68 36 72 C30 68 22 62 22 52 L18 26 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.2"
          fill={isSelected ? '#281414' : '#141414'}
          fillOpacity={isSelected ? '0.7' : '0.4'}
        />
        {/* Radar Arc Sweeps */}
        <path
          d="M26 36 C30 33 42 33 46 36"
          stroke={isSelected ? '#EF4444' : '#8E8E8E'}
          strokeWidth="1.5"
          strokeLinecap="round"
        />
        <path
          d="M29 44 C32 42 40 42 43 44"
          stroke={isSelected ? '#EF4444' : '#8E8E8E'}
          strokeWidth="1.5"
          strokeLinecap="round"
        />
        {/* Central Stealth Diamond */}
        <polygon
          points="36,46 41,52 36,58 31,52"
          fill={isSelected ? '#EF4444' : '#292929'}
          stroke="#F2F2F2"
          strokeWidth="1"
        />
      </svg>
    ),
  },
  {
    id: 'agent-3',
    callsign: 'CIPHER-03',
    designation: 'CIPHER',
    role: 'Threat Researcher',
    monogram: 'CP',
    defaultName: 'Agent Cipher',
    shieldIcon: (isSelected) => (
      <svg
        viewBox="0 0 72 88"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-14 h-16 sm:w-16 sm:h-20 transition-all duration-300"
      >
        {/* Hexagonal Cryptographic Shield */}
        <polygon
          points="36,6 66,22 66,62 36,82 6,62 6,22"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.75"
          fill={isSelected ? '#1F1414' : '#171717'}
        />
        {/* Inner Matrix Core */}
        <polygon
          points="36,16 56,28 56,56 36,70 16,56 16,28"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.2"
          fill={isSelected ? '#281414' : '#141414'}
          fillOpacity={isSelected ? '0.7' : '0.4'}
        />
        {/* Data Circuit Matrix Lines */}
        <line x1="28" y1="36" x2="44" y2="36" stroke={isSelected ? '#EF4444' : '#8E8E8E'} strokeWidth="1.5" />
        <line x1="36" y1="28" x2="36" y2="58" stroke={isSelected ? '#EF4444' : '#8E8E8E'} strokeWidth="1.5" />
        <circle cx="28" cy="36" r="2.5" fill={isSelected ? '#EF4444' : '#292929'} />
        <circle cx="44" cy="36" r="2.5" fill={isSelected ? '#EF4444' : '#292929'} />
        <circle cx="36" cy="46" r="3" fill="#F2F2F2" />
        <circle cx="36" cy="58" r="2" fill={isSelected ? '#EF4444' : '#292929'} />
      </svg>
    ),
  },
  {
    id: 'agent-4',
    callsign: 'PHANTOM-04',
    designation: 'HUNTER',
    role: 'Security Analyst',
    monogram: 'PH',
    defaultName: 'Agent Phantom',
    shieldIcon: (isSelected) => (
      <svg
        viewBox="0 0 72 88"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-14 h-16 sm:w-16 sm:h-20 transition-all duration-300"
      >
        {/* Interceptor Hunter Shield */}
        <path
          d="M36 6 L64 20 L58 56 C58 68 46 78 36 82 C26 78 14 68 14 56 L8 20 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.75"
          fill={isSelected ? '#1F1414' : '#171717'}
        />
        {/* Inner Plate */}
        <path
          d="M36 16 L52 26 L48 52 C48 61 40 68 36 71 C32 68 24 61 24 52 L20 26 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.2"
          fill={isSelected ? '#281414' : '#141414'}
          fillOpacity={isSelected ? '0.7' : '0.4'}
        />
        {/* Targeting Crosshair Reticle */}
        <circle
          cx="36"
          cy="42"
          r="10"
          stroke={isSelected ? '#EF4444' : '#8E8E8E'}
          strokeWidth="1.5"
          strokeDasharray="4 2"
        />
        <circle cx="36" cy="42" r="3" fill={isSelected ? '#EF4444' : '#292929'} />
        <circle cx="36" cy="42" r="1.5" fill="#F2F2F2" />
        {/* Hashmark Brackets */}
        <line x1="22" y1="42" x2="26" y2="42" stroke={isSelected ? '#F2F2F2' : '#8E8E8E'} strokeWidth="1.5" />
        <line x1="46" y1="42" x2="50" y2="42" stroke={isSelected ? '#F2F2F2' : '#8E8E8E'} strokeWidth="1.5" />
        <line x1="36" y1="28" x2="36" y2="32" stroke={isSelected ? '#F2F2F2' : '#8E8E8E'} strokeWidth="1.5" />
        <line x1="36" y1="52" x2="36" y2="56" stroke={isSelected ? '#F2F2F2' : '#8E8E8E'} strokeWidth="1.5" />
      </svg>
    ),
  },
  {
    id: 'agent-5',
    callsign: 'APEX-05',
    designation: 'COMMAND',
    role: 'Security Analyst',
    monogram: 'AX',
    defaultName: 'Agent Apex',
    shieldIcon: (isSelected) => (
      <svg
        viewBox="0 0 72 88"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-14 h-16 sm:w-16 sm:h-20 transition-all duration-300"
      >
        {/* Heavy Command Aegis Shield */}
        <path
          d="M36 6 L64 16 L66 52 C66 68 52 78 36 82 C20 78 6 68 6 52 L8 16 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.75"
          fill={isSelected ? '#1F1414' : '#171717'}
        />
        {/* Crown Chevron Top Accent */}
        <polygon
          points="30,14 36,8 42,14 36,17"
          fill={isSelected ? '#EF4444' : '#8E8E8E'}
        />
        {/* Inner Armor Plate */}
        <path
          d="M36 20 L54 28 L54 50 C54 62 44 70 36 73 C28 70 18 62 18 50 L18 28 Z"
          stroke={isSelected ? '#EF4444' : '#292929'}
          strokeWidth="1.2"
          fill={isSelected ? '#281414' : '#141414'}
          fillOpacity={isSelected ? '0.7' : '0.4'}
        />
        {/* Quad Processor Array */}
        <circle cx="31" cy="36" r="2.5" fill={isSelected ? '#EF4444' : '#292929'} />
        <circle cx="41" cy="36" r="2.5" fill={isSelected ? '#EF4444' : '#292929'} />
        <circle cx="31" cy="48" r="2.5" fill={isSelected ? '#EF4444' : '#292929'} />
        <circle cx="41" cy="48" r="2.5" fill={isSelected ? '#EF4444' : '#292929'} />
        <line x1="31" y1="36" x2="41" y2="48" stroke={isSelected ? '#F2F2F2' : '#8E8E8E'} strokeWidth="1" />
        <line x1="41" y1="36" x2="31" y2="48" stroke={isSelected ? '#F2F2F2' : '#8E8E8E'} strokeWidth="1" />
        <circle cx="36" cy="42" r="2" fill="#F2F2F2" />
      </svg>
    ),
  },
];

// Technical Starfield positions (deterministic to prevent hydration mismatch)
const STARS = [
  { x: 8, y: 14, size: 1.5, opacity: 0.5 },
  { x: 24, y: 8, size: 2, opacity: 0.75 },
  { x: 44, y: 18, size: 1, opacity: 0.45 },
  { x: 62, y: 11, size: 2, opacity: 0.85 },
  { x: 78, y: 15, size: 1.5, opacity: 0.65 },
  { x: 92, y: 9, size: 1, opacity: 0.4 },
  { x: 15, y: 30, size: 2, opacity: 0.7 },
  { x: 33, y: 36, size: 1.5, opacity: 0.55 },
  { x: 50, y: 24, size: 1, opacity: 0.4 },
  { x: 67, y: 32, size: 2, opacity: 0.8 },
  { x: 85, y: 26, size: 1.5, opacity: 0.5 },
  { x: 5, y: 44, size: 1, opacity: 0.35 },
  { x: 21, y: 50, size: 1.5, opacity: 0.55 },
  { x: 37, y: 45, size: 2, opacity: 0.7 },
  { x: 63, y: 46, size: 1, opacity: 0.45 },
  { x: 79, y: 52, size: 1.5, opacity: 0.6 },
  { x: 95, y: 38, size: 2, opacity: 0.65 },
  { x: 47, y: 10, size: 2, opacity: 0.75 },
  { x: 70, y: 20, size: 1, opacity: 0.4 },
];

export default function AnalystIdentityPage() {
  const router = useRouter();
  const [agentName, setAgentName] = useState('');
  const [selectedAvatar, setSelectedAvatar] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const existing = getAnalyst();
      if (existing?.name) {
        const search = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
        if (!search?.has('switch')) {
          router.replace('/investigate');
          return;
        }
        setAgentName(existing.name);
        const matchedIdx = AGENTS.findIndex(
          (a) => a.monogram === existing.avatarInitials,
        );
        if (matchedIdx !== -1) {
          setSelectedAvatar(matchedIdx);
        }
      }
    });

    return () => window.cancelAnimationFrame(frame);
  }, [router]);

  const handleInitiate = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsSubmitting(true);

    const chosenAgent = AGENTS[selectedAvatar];
    const finalName = agentName.trim() || chosenAgent.defaultName;

    try {
      setAnalyst({
        name: finalName,
        role: chosenAgent.role,
        avatarInitials: chosenAgent.monogram,
        theme: 'dark',
      });
    } catch (err) {
      console.error('Failed to save session profile', err);
    }

    setTimeout(() => {
      router.push('/investigate');
    }, 200);
  };

  return (
    <div className="min-h-screen w-full bg-[#080808] text-[#F2F2F2] flex flex-col justify-between relative overflow-hidden select-none font-sans">
      {/* ── Background Layer 1: Technical Starfield ── */}
      <div className="pointer-events-none absolute inset-0 z-0 overflow-hidden">
        {STARS.map((s, idx) => (
          <span
            key={idx}
            className="absolute rounded-full bg-[#F2F2F2] animate-pulse"
            style={{
              top: `${s.y}%`,
              left: `${s.x}%`,
              width: `${s.size}px`,
              height: `${s.size}px`,
              opacity: s.opacity,
              animationDuration: `${2.8 + (idx % 3)}s`,
              animationDelay: `${(idx % 5) * 0.4}s`,
            }}
          />
        ))}
      </div>

      {/* ── Background Layer 2: Fine Technical Grid Overlay ── */}
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-20"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(41, 41, 41, 0.4) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(41, 41, 41, 0.4) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />

      {/* ── Background Layer 3: Red Illumination Glow ── */}
      <div
        className="pointer-events-none absolute inset-0 z-0"
        style={{
          background:
            'radial-gradient(ellipse 65% 50% at 50% 48%, rgba(239, 68, 68, 0.12), transparent 72%)',
        }}
      />

      {/* ── Background Layer 4: Futuristic 3D Perspective Grid Floor ── */}
      <div className="pointer-events-none absolute bottom-0 left-0 right-0 h-44 sm:h-56 md:h-64 overflow-hidden [perspective:600px] z-0">
        <div
          className="absolute -inset-x-20 bottom-0 h-96 origin-bottom [transform:rotateX(72deg)]"
          style={{
            backgroundImage: `
              linear-gradient(to right, rgba(239, 68, 68, 0.18) 1px, transparent 1px),
              linear-gradient(to bottom, rgba(239, 68, 68, 0.18) 1px, transparent 1px)
            `,
            backgroundSize: '44px 44px',
            maskImage:
              'linear-gradient(to top, rgba(0,0,0,1) 15%, rgba(0,0,0,0.6) 65%, transparent 100%)',
            WebkitMaskImage:
              'linear-gradient(to top, rgba(0,0,0,1) 15%, rgba(0,0,0,0.6) 65%, transparent 100%)',
          }}
        />
        {/* Horizon Light Line */}
        <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[#EF4444]/60 to-transparent shadow-[0_0_20px_rgba(239,68,68,0.7)]" />
        <div className="absolute inset-0 bg-gradient-to-t from-[#080808] via-transparent to-transparent opacity-80" />
      </div>

      {/* ── TOP SECTION: Logo & Authentication Protocol ── */}
      <header className="relative z-10 pt-7 sm:pt-9 text-center px-4">
        <div className="flex flex-col items-center">
          {/* ThreatNova-AI Logo and Wordmark */}
          <div className="flex items-center gap-2.5 mb-1">
            <div className="w-7 h-7 rounded-lg bg-[#171717] border border-[#EF4444]/40 flex items-center justify-center shadow-[0_0_12px_rgba(239,68,68,0.25)]">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                className="w-4 h-4 text-[#EF4444]"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6l-8-4z" />
                <path d="M12 7v6m-3-3h6" strokeLinecap="round" />
              </svg>
            </div>
            <h2 className="text-xs sm:text-sm font-mono tracking-[0.38em] text-[#F2F2F2] font-bold uppercase">
              THREATNOVA-AI
            </h2>
          </div>
          {/* Subtitle */}
          <p className="text-[10px] sm:text-[11px] font-mono tracking-[0.3em] text-[#EF4444]/80 uppercase">
            AUTHENTICATION PROTOCOL
          </p>
        </div>
      </header>

      {/* ── MAIN INTERACTIVE SECTION ── */}
      <main className="relative z-10 w-full max-w-4xl mx-auto px-4 py-4 sm:py-6 flex flex-col items-center">
        {/* Large Elegant Heading */}
        <h1 className="text-3xl sm:text-4xl md:text-5xl font-light tracking-tight text-[#F2F2F2] text-center font-sans">
          Who are you, agent?
        </h1>

        {/* Identity Form */}
        <form onSubmit={handleInitiate} className="w-full mt-6 sm:mt-7 flex flex-col items-center">
          {/* Identity Designation Text Input */}
          <div className="w-full max-w-md text-center">
            <label
              htmlFor="agent-name-input"
              className="block text-[10px] sm:text-xs font-mono tracking-[0.25em] text-[#8E8E8E] uppercase font-semibold mb-2"
            >
              IDENTITY DESIGNATION
            </label>
            <input
              id="agent-name-input"
              type="text"
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              placeholder="Enter your agent name..."
              maxLength={32}
              className="w-full bg-[#171717] border border-[#292929] focus:border-[#EF4444] focus:ring-1 focus:ring-[#EF4444]/40 text-center text-sm sm:text-base font-mono text-[#F2F2F2] placeholder:text-[#8E8E8E]/70 py-2.5 sm:py-3 px-4 rounded-lg outline-none transition-all shadow-inner backdrop-blur-md"
              autoComplete="off"
              spellCheck="false"
            />
          </div>

          {/* 5 Selectable Agent Cards (Strictly 1 Horizontal Row on Desktop) */}
          <div className="w-full max-w-4xl mt-7 sm:mt-8">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 sm:gap-3.5">
              {AGENTS.map((agent, idx) => {
                const isSelected = selectedAvatar === idx;
                return (
                  <button
                    key={agent.id}
                    type="button"
                    onClick={() => setSelectedAvatar(idx)}
                    className={`group relative rounded-xl border p-3.5 sm:p-4 flex flex-col items-center justify-between text-center transition-all duration-300 backdrop-blur-md cursor-pointer ${
                      isSelected
                        ? 'bg-[#171717] border-[#EF4444] shadow-[0_0_25px_rgba(239,68,68,0.25)] ring-1 ring-[#EF4444]/50 scale-[1.02]'
                        : 'bg-[#171717]/60 border-[#292929] hover:border-[#292929] hover:bg-[#171717] text-[#8E8E8E]'
                    }`}
                  >
                    {/* Top Callsign */}
                    <span
                      className={`text-[10px] sm:text-[11px] font-mono tracking-wider font-semibold uppercase mb-2 transition-colors ${
                        isSelected ? 'text-[#EF4444] font-bold' : 'text-[#8E8E8E] group-hover:text-[#F2F2F2]'
                      }`}
                    >
                      {agent.callsign}
                    </span>

                    {/* Unique Futuristic Shield / Avatar Icon */}
                    <div className="my-2 flex items-center justify-center">
                      {agent.shieldIcon(isSelected)}
                    </div>

                    {/* Bottom Designation Badge */}
                    <div className="mt-2 w-full pt-2 border-t border-[#292929] flex items-center justify-center gap-1.5">
                      <span
                        className={`text-[9px] sm:text-[10px] font-mono tracking-widest uppercase font-semibold ${
                          isSelected ? 'text-[#F2F2F2] font-bold' : 'text-[#8E8E8E]'
                        }`}
                      >
                        {agent.designation}
                      </span>
                      {isSelected && (
                        <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] shadow-[0_0_6px_rgba(239,68,68,0.9)]" />
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Large Centered Outlined Initiate Connection Button */}
          <div className="w-full max-w-md mt-8 sm:mt-9">
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full border-2 border-[#292929] hover:border-[#EF4444] hover:text-[#EF4444] hover:shadow-[0_0_25px_rgba(239,68,68,0.35)] text-[#F2F2F2] font-mono text-xs sm:text-sm font-semibold tracking-[0.25em] py-3.5 px-6 rounded-lg transition-all duration-300 bg-[#171717]/80 hover:bg-[#171717] flex items-center justify-center gap-3 group uppercase cursor-pointer backdrop-blur-sm disabled:opacity-50"
            >
              {isSubmitting ? (
                <span>CONNECTING…</span>
              ) : (
                <>
                  <span>INITIATE CONNECTION</span>
                  <span className="text-base group-hover:translate-x-1.5 transition-transform duration-200">
                    →
                  </span>
                </>
              )}
            </button>
          </div>
        </form>
      </main>

      {/* ── FOOTER: Node, Terms, and System Status ── */}
      <footer className="relative z-10 w-full max-w-5xl mx-auto px-6 py-5 border-t border-[#292929] mt-auto">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2.5 text-[10px] sm:text-[11px] font-mono tracking-widest text-[#8E8E8E] uppercase">
          <div className="flex items-center gap-1.5">
            <Lock size={12} className="text-[#8E8E8E]" />
            <span>SECURE NODE</span>
          </div>

          <div className="text-[#8E8E8E] hover:text-[#F2F2F2] cursor-default transition-colors">
            PRIVACY TERMS
          </div>

          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-pulse shadow-[0_0_8px_rgba(239,68,68,0.9)]" />
            <span className="text-[#8E8E8E] font-semibold">SYSTEM STATUS: OPERATIONAL</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
