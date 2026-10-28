import { Network } from 'lucide-react';
import DemoDataBadge from '@/components/DemoDataBadge';
import GraphExplorer from '@/components/GraphExplorer';
import PageHeader from '@/components/PageHeader';

export default function ThreatGraphPage() {
  return (
    <div className="space-y-5">
      <PageHeader
        title="Threat intelligence graph"
        subtitle="Explore hierarchical relationships: target indicator, telemetry categories, and empirical findings."
      >
        <DemoDataBadge label="ROOT TREE GRAPH" />
      </PageHeader>

      <div
        role="note"
        className="flex items-start gap-3 rounded-lg border border-tn-border bg-tn-surface px-4 py-3"
      >
        <Network size={16} className="mt-0.5 shrink-0 text-tn-info" aria-hidden="true" />
        <p className="text-xs leading-5 text-tn-muted">
          Hierarchical Root Tree layout mapping empirical telemetry: Target Indicator (Root) → Telemetry Categories (Branches) → Evidence Observations (Leaves).
        </p>
      </div>

      <GraphExplorer />
    </div>
  );
}
