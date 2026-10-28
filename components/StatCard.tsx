import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: string | number;
  detail?: string;
  trend?: 'up' | 'down' | 'neutral';
  accent?: string;
}

export default function StatCard({ icon: Icon, label, value, detail, accent }: StatCardProps) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-tn-border bg-tn-card p-4">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-tn-border/70 bg-tn-surface">
        <Icon size={18} className={accent || 'text-tn-muted'} />
      </div>
      <div className="min-w-0">
        <p className="text-xs text-tn-muted">{label}</p>
        <p className="text-xl font-semibold tracking-tight text-tn-text">{value}</p>
        {detail && <p className="mt-0.5 text-[11px] text-tn-muted">{detail}</p>}
      </div>
    </div>
  );
}
