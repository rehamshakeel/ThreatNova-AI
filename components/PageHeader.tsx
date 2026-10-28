interface PageHeaderProps {
  title: string;
  subtitle?: string;
  children?: React.ReactNode; // right-side actions
}

export default function PageHeader({ title, subtitle, children }: PageHeaderProps) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6">
      <div>
        <h1 className="text-xl font-bold text-tn-text">{title}</h1>
        {subtitle && <p className="text-sm text-tn-muted mt-0.5">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  );
}
