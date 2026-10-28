import { severityBg, severityLabel } from '@/lib/utils';
import type { Severity } from '@/lib/types';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export default function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${severityBg(severity)} ${className}`}>
      {severityLabel(severity)}
    </span>
  );
}
