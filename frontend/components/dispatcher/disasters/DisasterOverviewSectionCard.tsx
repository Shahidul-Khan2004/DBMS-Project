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
  fillBody = false,
  previewMode = false,
}: {
  title: string;
  subtitle?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  scrollBody?: boolean;
  fillBody?: boolean;
  previewMode?: boolean;
}) {
  const sectionClasses = [
    "flex min-h-0 flex-col overflow-hidden rounded-xl border border-slate-200/90 bg-white shadow-sm",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const bodyPadding = previewMode ? "py-3" : "py-4";

  const bodyClasses = [
    scrollBody
      ? `min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-5 ${bodyPadding}`
      : previewMode
        ? `flex min-h-0 flex-1 flex-col px-5 ${bodyPadding}`
        : fillBody
          ? `min-h-0 flex-1 overflow-hidden px-5 ${bodyPadding}`
          : `px-5 ${bodyPadding}`,
    bodyClassName,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <section className={sectionClasses}>
      <header
        className={`flex shrink-0 ${previewMode ? "items-center" : "items-start"} justify-between gap-3 border-b border-slate-100 px-5 ${previewMode ? "py-3" : "py-4"}`}
      >
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
