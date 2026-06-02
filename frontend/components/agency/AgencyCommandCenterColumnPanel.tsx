import type { ReactNode } from "react";

function ColumnCountBadge({
  count,
  loading,
}: {
  count: number | null;
  loading: boolean;
}) {
  if (loading) {
    return (
      <span
        className="inline-flex min-w-[1.25rem] items-center justify-center rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-400"
        aria-hidden
      >
        —
      </span>
    );
  }

  return (
    <span className="inline-flex min-w-[1.25rem] items-center justify-center rounded-full bg-[#E8F2FF] px-2 py-0.5 text-xs font-semibold text-[#002D62]">
      {count ?? "—"}
    </span>
  );
}

export function AgencyCommandCenterColumnPanel({
  title,
  count,
  countLoading,
  subtitle,
  headerAction,
  children,
}: {
  title: string;
  count: number | null;
  countLoading: boolean;
  subtitle: string;
  headerAction?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm lg:h-full lg:min-h-0 lg:overflow-hidden">
      <header className="mb-3 shrink-0">
        <div className="flex items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
            <ColumnCountBadge count={count} loading={countLoading} />
          </div>
          {headerAction ? <div className="shrink-0">{headerAction}</div> : null}
        </div>
        <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>
      </header>
      <div className="flex flex-col gap-3 lg:min-h-0 lg:flex-1 lg:overflow-hidden">
        <div className="flex flex-col gap-3 lg:min-h-0 lg:flex-1 lg:overflow-y-auto lg:pr-1 [scrollbar-width:thin] [scrollbar-color:theme(colors.slate.300)_transparent]">
          {children}
        </div>
      </div>
    </section>
  );
}
