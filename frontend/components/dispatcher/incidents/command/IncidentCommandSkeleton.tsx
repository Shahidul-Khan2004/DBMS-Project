"use client";

export function IncidentCommandSkeleton() {
  return (
    <div
      className="flex min-h-0 flex-1 flex-col gap-2 lg:gap-3 lg:overflow-hidden"
      aria-busy="true"
      aria-label="Loading incident command"
    >
      <header className="shrink-0 space-y-1">
        <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1.5">
          <div className="h-3 w-56 animate-pulse rounded bg-slate-200" />
          <div className="flex flex-wrap items-center justify-end gap-1.5 sm:gap-2">
            <div className="h-8 w-28 animate-pulse rounded-md bg-slate-200" />
            <div className="h-8 w-24 animate-pulse rounded-md bg-slate-200" />
            <div className="h-8 w-28 animate-pulse rounded-md bg-slate-200" />
          </div>
        </div>
        <section className="rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm sm:p-4">
          <div className="min-w-0 space-y-0.5">
            <div className="h-6 w-2/3 max-w-md animate-pulse rounded bg-slate-200" />
            <div className="h-4 w-1/2 max-w-sm animate-pulse rounded bg-slate-200" />
            <div className="h-4 w-3/4 max-w-lg animate-pulse rounded bg-slate-200" />
          </div>
        </section>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,55fr)_minmax(0,45fr)] lg:gap-3 lg:overflow-hidden">
        <div className="min-h-0 flex-1 animate-pulse rounded-xl bg-white lg:h-full" />
        <div className="min-h-0 flex-1 animate-pulse rounded-xl bg-white lg:h-full" />
      </div>
    </div>
  );
}
