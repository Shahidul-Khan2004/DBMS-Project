"use client";

import type { ReactNode } from "react";
import { RequiredMarker } from "@/components/dispatcher/FieldLabel";

export function CommandSectionCard({
  title,
  subtitle,
  titleRequired = false,
  headerAction,
  belowHeader,
  children,
  className = "",
  bodyClassName = "",
  fillHeight = false,
  scrollableBody = false,
}: {
  title: string;
  subtitle?: string;
  titleRequired?: boolean;
  headerAction?: ReactNode;
  belowHeader?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  fillHeight?: boolean;
  scrollableBody?: boolean;
}) {
  const sectionClasses = [
    "rounded-xl border border-slate-200/90 bg-white p-4 shadow-sm sm:p-5",
    fillHeight ? "flex h-full min-h-0 flex-col" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const bodyClasses = [
    "mt-3",
    fillHeight ? "flex min-h-0 flex-1 flex-col" : "",
    bodyClassName,
  ]
    .filter(Boolean)
    .join(" ");

  const contentClasses = scrollableBody
    ? "min-h-0 flex-1 overflow-y-auto overscroll-y-contain pr-0.5"
    : "";

  return (
    <section className={sectionClasses}>
      <div className="flex shrink-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-slate-900">
            {title}
            {titleRequired ? <RequiredMarker /> : null}
          </h3>
          {subtitle ? (
            <p className="mt-0.5 text-xs text-slate-600">{subtitle}</p>
          ) : null}
        </div>
        {headerAction ? (
          <div className="shrink-0">{headerAction}</div>
        ) : null}
      </div>
      {belowHeader ? (
        <div className="mt-2 shrink-0">{belowHeader}</div>
      ) : null}
      <div className={bodyClasses}>
        {scrollableBody ? (
          <div className={contentClasses}>{children}</div>
        ) : (
          children
        )}
      </div>
    </section>
  );
}
