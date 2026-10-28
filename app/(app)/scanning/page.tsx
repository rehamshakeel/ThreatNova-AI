import { Suspense } from 'react';
import Link from 'next/link';
import ScanWorkflow from '@/components/ScanWorkflow';
import { isIndicatorType, isValidIndicator } from '@/lib/indicators';

type SearchValue = string | string[] | undefined;

async function ScanningContent({
  searchParams,
}: {
  searchParams: Promise<{ indicator?: SearchValue; type?: SearchValue }>;
}) {
  const params = await searchParams;
  const indicator = typeof params.indicator === 'string' ? params.indicator.trim() : '';
  const type = typeof params.type === 'string' ? params.type : '';

  if (!indicator || !isIndicatorType(type) || !isValidIndicator(indicator, type)) {
    return (
      <div className="mx-auto max-w-3xl rounded-xl border border-tn-border bg-tn-surface p-6">
        <h1 className="text-lg font-semibold text-tn-text">Indicator not ready</h1>
        <p className="mt-2 text-sm text-tn-muted">
          Return to the overview and enter a valid IP address, domain, URL, or file hash to
          start the demonstration workflow.
        </p>
        <Link
          href="/dashboard"
          className="mt-5 inline-flex rounded-lg border border-tn-border bg-tn-card px-3 py-2 text-sm font-medium text-tn-text hover:border-tn-muted"
        >
          Back to overview
        </Link>
      </div>
    );
  }

  return <ScanWorkflow indicator={indicator} type={type} />;
}

export default function ScanningPage({
  searchParams,
}: {
  searchParams: Promise<{ indicator?: SearchValue; type?: SearchValue }>;
}) {
  return (
    <Suspense
      fallback={
        <div className="mx-auto max-w-3xl rounded-xl border border-tn-border bg-tn-surface p-6 text-sm text-tn-muted">
          Preparing demonstration workflow…
        </div>
      }
    >
      <ScanningContent searchParams={searchParams} />
    </Suspense>
  );
}
