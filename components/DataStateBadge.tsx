export type DataState = 'demo' | 'pending' | 'unavailable' | 'error';

const stateClasses: Record<DataState, string> = {
  demo: 'border-tn-info/25 bg-tn-info/10 text-tn-info',
  pending: 'border-tn-warn/25 bg-tn-warn/10 text-tn-warn',
  unavailable: 'border-tn-border bg-tn-card text-tn-muted',
  error: 'border-tn-danger/25 bg-tn-danger/10 text-tn-danger',
};

const stateLabels: Record<DataState, string> = {
  demo: 'Demo data',
  pending: 'Pending',
  unavailable: 'Unavailable',
  error: 'Error',
};

export default function DataStateBadge({ state, label }: { state: DataState; label?: string }) {
  return (
    <span className={`inline-flex w-fit items-center rounded border px-2 py-0.5 text-[9px] font-mono font-semibold uppercase tracking-wider ${stateClasses[state]}`}>
      {label || stateLabels[state]}
    </span>
  );
}
