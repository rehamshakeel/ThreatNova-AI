// lib/storage.ts
// localStorage helpers — non-sensitive demo data only

import type {
  Alert,
  AnalystProfile,
  InterfacePreferences,
  Investigation,
} from './types';

const KEYS = {
  analyst: 'tn_analyst',
  alerts: 'tn_alerts',
  preferences: 'tn_preferences',
  investigations: 'tn_investigations',
} as const;

const DEFAULT_PREFERENCES: InterfacePreferences = {
  compactTables: false,
  reduceMotion: false,
};

function safeGet<T>(key: string): T | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch (error) {
    console.error(`Unable to read demo preference "${key}".`, error);
    return null;
  }
}

function safeSet(key: string, value: unknown): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (error) {
    console.error(`Unable to save demo preference "${key}".`, error);
    throw error;
  }
}

// ── Analyst ──
export function getAnalyst(): AnalystProfile | null {
  return safeGet<AnalystProfile>(KEYS.analyst);
}

export function setAnalyst(profile: AnalystProfile): void {
  safeSet(KEYS.analyst, profile);
}

export function clearAnalyst(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(KEYS.analyst);
}

// ── Alerts ──
export function getAlerts(): Alert[] {
  return safeGet<Alert[]>(KEYS.alerts) ?? [];
}

export function saveAlerts(alerts: Alert[]): void {
  safeSet(KEYS.alerts, alerts);
}

// ── Interface preferences ──
export function getInterfacePreferences(): InterfacePreferences {
  return safeGet<InterfacePreferences>(KEYS.preferences) ?? DEFAULT_PREFERENCES;
}

export function setInterfacePreferences(preferences: InterfacePreferences): void {
  safeSet(KEYS.preferences, preferences);
}

export function resetDemoData(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(KEYS.alerts);
  localStorage.removeItem(KEYS.preferences);
  localStorage.removeItem(KEYS.investigations);
}

// ── Investigations ──
export function getSavedInvestigations(): Investigation[] {
  return safeGet<Investigation[]>(KEYS.investigations) ?? [];
}

export function saveInvestigation(investigation: Investigation): void {
  const current = getSavedInvestigations();
  const next = [investigation, ...current.filter((inv) => inv.id !== investigation.id)].slice(0, 30);
  safeSet(KEYS.investigations, next);
}

