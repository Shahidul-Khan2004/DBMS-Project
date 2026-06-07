"use client";

import type { ReactNode } from "react";

export function DisasterOverviewSectionCard({
  title,
  subtitle,
  right,
  children,
  className = "",
  bodyClassName = "",
  scrollBody = false,
}: {
  title: string;
  subtitle?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  scrollBody?: boolean;
}) {
  const sectionClasses = [
    "flex min-h-0 flex-col overflow-hidden rounded-xl border border-slate-200/90 bg-white shadow-sm",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const bodyClasses = [
    scrollBody
      ? "min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-5 py-4"
      : "px-5 py-4",
    bodyClassName,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <section className={sectionClasses}>
      <header className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
          {subtitle ? (
            <p className="mt-0.5 text-xs text-slate-600">{subtitle}</p>
          ) : null}
        </div>
        {right ? <div className="shrink-0">{right}</div> : null}
      </header>

      <div className={bodyClasses}>{children}</div>
    </section>
  );
}
