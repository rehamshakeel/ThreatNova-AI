'use client';

import { useEffect, useRef, useState } from 'react';
import { Search, ShieldCheck } from 'lucide-react';
import { getAnalyst } from '@/lib/storage';
import type { AnalystProfile } from '@/lib/types';

export default function DashboardHeader() {
  const [analyst, setAnalyst] = useState<AnalystProfile | null>(null);
  const searchInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      setAnalyst(getAnalyst());
      if (searchInput.current) {
        searchInput.current.value =
          new URLSearchParams(window.location.search).get('q') ?? '';
      }
    });

    return () => window.cancelAnimationFrame(frame);
  }, []);

  return (
    <header className="sticky top-0 z-30 flex h-[72px] items-center gap-3 border-b border-tn-border bg-tn-bg/95 px-4 pl-16 backdrop-blur sm:px-6 sm:pl-16 lg:px-8">
      <form action="/dashboard" method="get" className="relative w-full max-w-xl">
        <Search
          size={16}
          aria-hidden="true"
          className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-tn-muted"
        />
        <input
          aria-label="Search investigations"
          name="q"
          type="search"
          ref={searchInput}
          placeholder="Search investigations…"
          className="h-10 w-full rounded-lg border border-tn-border bg-tn-surface pl-10 pr-4 text-sm text-tn-text placeholder:text-tn-muted/70 focus:border-tn-muted focus:outline-none"
        />
      </form>

      <div className="ml-auto flex shrink-0 items-center gap-3">
        <div className="hidden items-center gap-2 rounded-full border border-tn-border/80 bg-tn-surface px-3 py-1.5 text-[11px] font-medium tracking-wide text-tn-muted sm:flex">
          <span className="h-1.5 w-1.5 rounded-full bg-tn-warn" />
          DEMO WORKSPACE
        </div>
        <div className="flex items-center gap-2.5 border-l border-tn-border pl-3 sm:pl-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-full border border-tn-border bg-tn-card text-sm font-semibold text-tn-text">
            {analyst?.avatarInitials || <ShieldCheck size={17} aria-hidden="true" />}
          </div>
          <div className="hidden min-w-0 sm:block">
            <p className="max-w-36 truncate text-sm font-medium text-tn-text">
              {analyst?.name || 'Workspace analyst'}
            </p>
            <p className="text-xs text-tn-muted truncate max-w-36">{analyst?.role || 'Security Analyst'}</p>
          </div>
        </div>
      </div>
    </header>
  );
}
