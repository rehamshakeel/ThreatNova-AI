import { Suspense } from 'react';
import InvestigationHistory from '@/components/InvestigationHistory';

async function HistoryContent({
  searchParams,
}: {
  searchParams: Promise<{ investigation?: string | string[] }>;
}) {
  const params = await searchParams;
  const selectedId = typeof params.investigation === 'string' ? params.investigation : 'inv-001';
  return <InvestigationHistory initialSelectedId={selectedId} />;
}

export default function HistoryPage({
  searchParams,
}: {
  searchParams: Promise<{ investigation?: string | string[] }>;
}) {
  return (
    <Suspense
      fallback={
        <div className="rounded-xl border border-tn-border bg-tn-surface p-6 text-sm text-tn-muted">
          Loading sample history…
        </div>
      }
    >
      <HistoryContent searchParams={searchParams} />
    </Suspense>
  );
}
