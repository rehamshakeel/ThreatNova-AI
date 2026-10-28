'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Bell, ChevronLeft, ChevronRight, FileSearch, Globe2, History,
  Home, LogOut, Menu, Network, Search, Settings, Shield,
} from 'lucide-react';
import { getAnalyst, clearAnalyst } from '@/lib/storage';

const NAV_ITEMS = [
  { href: '/dashboard', icon: Home, label: 'Overview' },
  { href: '/investigate', icon: Search, label: 'New Investigation' },
  { href: '/graph', icon: Network, label: 'Threat Graph' },
  { href: '/findings', icon: FileSearch, label: 'Findings & Evidence' },
  { href: '/intelligence', icon: Globe2, label: 'Domain & Network' },
  { href: '/history', icon: History, label: 'Investigation History' },
  { href: '/alerts', icon: Bell, label: 'Alerts' },
  { href: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [analyst, setAnalyst] = useState<ReturnType<typeof getAnalyst>>(null);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setAnalyst(getAnalyst()));
    return () => window.cancelAnimationFrame(frame);
  }, []);

  const handleLogout = () => {
    clearAnalyst();
    router.push('/');
  };

  const isActive = (href: string) => {
    const path = href.split('#')[0];
    if (href.includes('#')) return pathname === '/scanning';
    if (path === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(path);
  };

  const sidebarContent = (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-tn-border">
        <div className="w-9 h-9 rounded-xl bg-tn-card border border-tn-border flex items-center justify-center flex-shrink-0">
          <Shield size={18} className="text-tn-text" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <h1 className="text-sm font-bold text-tn-text truncate">ThreatNova AI</h1>
            <p className="text-[10px] text-tn-muted truncate">Investigation workspace</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
        {NAV_ITEMS.map(({ href, icon: Icon, label }) => (
          <Link
            key={href}
            href={href}
            onClick={() => setMobileOpen(false)}
            aria-current={isActive(href) ? 'page' : undefined}
            className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
              isActive(href)
                ? 'border-l-2 border-[#EF4444] bg-tn-card text-[#F2F2F2] font-medium'
                : 'text-tn-muted hover:bg-tn-card/50 hover:text-tn-text'
            }`}
            title={collapsed ? label : undefined}
          >
            <Icon size={18} className="flex-shrink-0" />
            {!collapsed && <span className="truncate">{label}</span>}
          </Link>
        ))}
      </nav>

      {/* Analyst profile + collapse toggle */}
      <div className="border-t border-tn-border px-3 py-3 space-y-2">
        {analyst && !collapsed && (
          <div className="flex items-center gap-2 px-1">
            <span className="text-lg">{analyst.avatarInitials}</span>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium text-tn-text truncate">{analyst.name}</p>
              <p className="text-[10px] text-tn-muted truncate">{analyst.role || 'Analyst'}</p>
            </div>
            <button
              onClick={handleLogout}
              className="p-1 rounded hover:bg-tn-card text-tn-muted hover:text-tn-text"
              title="Sign out"
            >
              <LogOut size={14} />
            </button>
          </div>
        )}
        {/* Desktop collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="hidden lg:flex items-center justify-center w-full p-1.5 rounded-lg text-tn-muted hover:bg-tn-card hover:text-tn-text"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setMobileOpen(true)}
        className="lg:hidden fixed top-3 left-3 z-50 p-2 rounded-lg bg-tn-surface border border-tn-border text-tn-text"
        aria-label="Open navigation"
        aria-expanded={mobileOpen}
        aria-controls="workspace-navigation"
      >
        <Menu size={20} />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <button
          type="button"
          className="lg:hidden fixed inset-0 bg-black/60 z-40"
          onClick={() => setMobileOpen(false)}
          aria-label="Close navigation"
        />
      )}

      {/* Sidebar */}
      <aside
        id="workspace-navigation"
        aria-label="Workspace navigation"
        className={`
          fixed lg:sticky top-0 left-0 z-40 h-screen
          bg-tn-surface border-r border-tn-border
          transition-all duration-200
          ${collapsed ? 'w-16' : 'w-60'}
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}
      >
        {sidebarContent}
      </aside>
    </>
  );
}
