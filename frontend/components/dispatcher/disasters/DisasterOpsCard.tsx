"use client";

import type { ReactNode } from "react";

export function DisasterOpsCard({
  title,
  subtitle,
  headerAction,
  children,
  className = "",
  bodyClassName = "",
  fillHeight = false,
  scrollBody = false,
}: {
  title: string;
  subtitle?: string;
  headerAction?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  fillHeight?: boolean;
  scrollBody?: boolean;
}) {
  const outerClasses = [
    "rounded-xl border border-slate-200/90 bg-white shadow-sm",
    fillHeight ? "flex min-h-0 flex-col overflow-hidden" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const bodyClasses = [
    scrollBody || fillHeight
      ? "min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-5 py-4"
      : "px-5 py-4",
    bodyClassName,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <section className={outerClasses}>
      <div className="flex shrink-0 flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
          {subtitle ? (
            <p className="mt-0.5 text-xs text-slate-600">{subtitle}</p>
          ) : null}
        </div>
        {headerAction ? <div className="shrink-0">{headerAction}</div> : null}
      </div>
      <div className={bodyClasses}>{children}</div>
    </section>
  );
}
