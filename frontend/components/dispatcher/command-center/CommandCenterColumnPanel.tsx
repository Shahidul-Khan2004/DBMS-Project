import type { ReactNode } from "react";
import {
  getCommandCenterColumnCountClasses,
  type CommandCenterColumn,
} from "@/components/dispatcher/command-center/columnAccentStyles";

function ColumnCountBadge({
  count,
  loading,
  column,
}: {
  count: number | null;
  loading: boolean;
  column: CommandCenterColumn;
}) {
  const accentClasses = getCommandCenterColumnCountClasses(column);

  if (loading) {
    return (
      <span
        className={`inline-flex min-w-[1.25rem] items-center justify-center rounded-full px-2 py-0.5 text-xs font-semibold text-slate-400 ${accentClasses}`}
        aria-hidden
      >
        —
      </span>
    );
  }

  return (
    <span
      className={`inline-flex min-w-[1.25rem] items-center justify-center rounded-full px-2 py-0.5 text-xs font-semibold ${accentClasses}`}
    >
      {count ?? "—"}
    </span>
  );
}

export function CommandCenterColumnPanel({
  column,
  title,
  count,
  countLoading,
  subtitle,
  pinned,
  children,
}: {
  column: CommandCenterColumn;
  title: string;
  count: number | null;
  countLoading: boolean;
  subtitle: string;
  pinned?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm lg:h-full lg:min-h-0 lg:overflow-hidden">
      <header className="mb-3 shrink-0">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
          <ColumnCountBadge count={count} loading={countLoading} column={column} />
        </div>
        <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>
      </header>
      {pinned ? <div className="mb-3 shrink-0">{pinned}</div> : null}
      <div className="flex flex-col gap-3 lg:min-h-0 lg:flex-1 lg:overflow-hidden">
        <div className="flex flex-col gap-3 lg:min-h-0 lg:flex-1 lg:overflow-y-auto lg:pr-1">
          {children}
        </div>
      </div>
    </section>
  );
}

export function CommandCenterDropZonePlaceholder({
  children,
}: {
  children: string;
}) {
  return (
    <div className="shrink-0 rounded-lg border border-dashed border-slate-200 bg-slate-50/50 px-3 py-2 text-center text-xs text-slate-500">
      {children}
    </div>
  );
}
