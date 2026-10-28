import { Suspense } from 'react';
import type { DataState } from '@/components/DataStateBadge';
import NetworkIntelligencePage from '@/components/NetworkIntelligencePage';

type SearchValue = string | string[] | undefined;

async function IntelligenceContent({
  searchParams,
}: {
  searchParams: Promise<{ indicator?: SearchValue; type?: SearchValue; state?: SearchValue }>;
}) {
  const params = await searchParams;
  const initialIndicator = typeof params.indicator === 'string' ? params.indicator.trim() : undefined;
  const initialType = typeof params.type === 'string' ? params.type : undefined;
  const rawState = typeof params.state === 'string' ? params.state : undefined;
  const initialState =
    rawState && ['demo', 'pending', 'unavailable', 'error'].includes(rawState)
      ? (rawState as DataState)
      : undefined;

  return (
    <NetworkIntelligencePage
      initialIndicator={initialIndicator}
      initialType={initialType}
      initialState={initialState}
    />
  );
}

export default function IntelligenceRoute({
  searchParams,
}: {
  searchParams: Promise<{ indicator?: SearchValue; type?: SearchValue; state?: SearchValue }>;
}) {
  return (
    <Suspense
      fallback={
        <div className="rounded-xl border border-tn-border bg-tn-surface p-6 text-sm text-tn-muted">
          Loading Domain &amp; Network Intelligence telemetry…
        </div>
      }
    >
      <IntelligenceContent searchParams={searchParams} />
    </Suspense>
  );
}
