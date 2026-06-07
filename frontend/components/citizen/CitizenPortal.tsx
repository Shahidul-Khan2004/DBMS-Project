import type { ReactNode } from "react";
import Link from "next/link";
import { ArrowLeft, ArrowRight, MapPin } from "lucide-react";

export function CitizenBackButton({
  href,
  label,
  className = "",
}: {
  href: string;
  label: string;
  className?: string;
}) {
  return (
    <Link
      href={href}
      className={`inline-flex h-9 shrink-0 items-center justify-center gap-2 rounded-full border border-[#002D62]/25 bg-white px-3 text-sm font-semibold text-[#002D62] shadow-sm shadow-[#002D62]/10 transition-colors hover:border-[#002D62]/40 hover:bg-[#E8F2FF] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0B3FE8]/35 focus-visible:ring-offset-2 ${className}`}
    >
      <ArrowLeft className="h-4 w-4" aria-hidden />
      {label}
    </Link>
  );
}

type CitizenPageHeaderProps = {
  title: string;
  subtitle: string;
  action?: ReactNode;
};

export function CitizenPageHeader({
  title,
  subtitle,
  action,
}: CitizenPageHeaderProps) {
  return (
    <div className="flex flex-col gap-3 rounded-2xl border border-[#002D62]/10 bg-white px-4 py-4 shadow-sm shadow-[#002D62]/5 sm:flex-row sm:items-center sm:justify-between sm:px-5">
      <div className="min-w-0">
        <h2 className="text-xl font-bold text-[#002D62] sm:text-2xl">{title}</h2>
        <p className="mt-1 max-w-2xl text-sm leading-5 text-[#42547A]">
          {subtitle}
        </p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

type CitizenSectionCardProps = {
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  topBar?: ReactNode;
  headerAction?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
};

export function CitizenSectionCard({
  title,
  subtitle,
  icon,
  topBar,
  headerAction,
  children,
  className = "",
  contentClassName = "",
}: CitizenSectionCardProps) {
  return (
    <section
      className={`overflow-hidden rounded-2xl border border-[#002D62]/10 bg-white shadow-sm shadow-[#002D62]/5 ${className}`}
    >
      {topBar ? (
        <div className="border-b border-[#002D62]/10 px-4 py-3 sm:px-5">
          {topBar}
        </div>
      ) : null}
      <header className="shrink-0 border-b border-[#002D62]/10 px-4 py-3.5 sm:px-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            {icon ? (
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[#EFF6FF] text-[#002D62]">
                {icon}
              </div>
            ) : null}
            <div className="min-w-0">
              <h3 className="text-lg font-semibold text-[#002D62]">{title}</h3>
              {subtitle ? (
                <p className="mt-1 text-sm leading-5 text-[#42547A]">
                  {subtitle}
                </p>
              ) : null}
            </div>
          </div>
          {headerAction ? <div className="shrink-0">{headerAction}</div> : null}
        </div>
      </header>
      <div className={`p-4 sm:p-5 ${contentClassName}`}>{children}</div>
    </section>
  );
}

export function CitizenRecordCard({
  children,
  id,
}: {
  children: ReactNode;
  id?: string;
}) {
  return (
    <article
      id={id}
      className="rounded-2xl border border-[#002D62]/10 bg-white p-4 shadow-sm shadow-[#002D62]/5 transition-shadow hover:shadow-md"
    >
      {children}
    </article>
  );
}

export function CitizenMetaItem({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <p className="min-w-0 text-sm leading-6 text-[#42547A]">
      <span className="font-semibold text-slate-800">{label}:</span>{" "}
      <span className="break-words">{value || "-"}</span>
    </p>
  );
}

export function CitizenLocationPill({ children }: { children: ReactNode }) {
  return (
    <div className="flex gap-2 rounded-xl bg-[#F0F7F4] px-3 py-2 text-sm leading-6 text-[#42547A]">
      <MapPin className="mt-1 h-4 w-4 shrink-0 text-[#006747]" aria-hidden />
      <p className="min-w-0">
        <span className="font-semibold text-slate-800">Location:</span>{" "}
        <span className="break-words">{children || "-"}</span>
      </p>
    </div>
  );
}

export function ReportIncidentLink({ className = "" }: { className?: string }) {
  return (
    <Link
      href="/dashboard/citizen/report-new"
      className={`inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-[#B91C1C] px-5 text-sm font-bold text-white shadow-sm shadow-[#B91C1C]/20 transition-colors hover:bg-[#991B1B] ${className}`}
    >
      Report New Incident
      <ArrowRight className="h-4 w-4" aria-hidden />
    </Link>
  );
}

export function getCitizenFriendlyError(
  err: unknown,
  fallback = "We could not load this information right now. Please try again.",
) {
  if (!(err instanceof Error)) return fallback;

  const message = err.message.trim();
  if (!message) return fallback;

  if (/internal server error|request failed|unexpected error/i.test(message)) {
    return fallback;
  }

  return message;
}
