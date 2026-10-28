import type { Severity } from './types';

export function severityLabel(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export function severityBg(severity: Severity): string {
  const styles: Record<Severity, string> = {
    critical: 'border-[#EF4444]/40 bg-[#EF4444]/15 text-[#EF4444]',
    high: 'border-[#EF4444]/30 bg-[#EF4444]/10 text-[#EF4444]',
    medium: 'border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444]',
    low: 'border-[#292929] bg-[#171717] text-[#F2F2F2]',
    info: 'border-[#292929] bg-[#171717] text-[#8E8E8E]',
  };
  return styles[severity];
}

export function riskScoreColor(score: number): string {
  if (score >= 80) return 'text-[#EF4444]';
  if (score >= 50) return 'text-[#EF4444]';
  if (score >= 25) return 'text-[#8E8E8E]';
  return 'text-[#F2F2F2]';
}

export function riskScoreBgColor(score: number): string {
  if (score >= 80) return '#EF4444';
  if (score >= 50) return '#EF4444';
  if (score >= 25) return '#8E8E8E';
  return '#F2F2F2';
}
