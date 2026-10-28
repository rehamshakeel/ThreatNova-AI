import type { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  message: string;
  action?: React.ReactNode;
}

export default function EmptyState({ icon: Icon, title, message, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-14 h-14 rounded-2xl bg-tn-card border border-tn-border flex items-center justify-center mb-4">
        <Icon size={24} className="text-tn-muted" />
      </div>
      <h3 className="text-sm font-semibold text-tn-text mb-1">{title}</h3>
      <p className="text-xs text-tn-muted max-w-xs">{message}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
