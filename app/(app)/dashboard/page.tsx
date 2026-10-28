import { Suspense } from 'react';
import DashboardHome from '@/components/DashboardHome';

async function DashboardResults({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; completed?: string }>;
}) {
  const { q = '', completed = '' } = await searchParams;

  return <DashboardHome searchQuery={q} showCompletion={completed === '1'} />;
}

export default function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; completed?: string }>;
}) {
  return (
    <Suspense
      fallback={
        <div className="rounded-xl border border-tn-border bg-tn-surface p-6 text-sm text-tn-muted">
          Loading workspace…
        </div>
      }
    >
      <DashboardResults searchParams={searchParams} />
    </Suspense>
  );
}
