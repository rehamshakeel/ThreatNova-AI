export default function DemoDataBadge({ label = 'DEMO DATA' }: { label?: string }) {
  return (
    <span className="inline-flex w-fit items-center rounded-md border border-tn-warn/30 bg-tn-warn/10 px-2.5 py-1 text-[10px] font-semibold tracking-wide text-tn-warn">
      {label}
    </span>
  );
}
