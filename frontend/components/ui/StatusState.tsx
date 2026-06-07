import type { ReactNode } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Info,
  Loader2,
  SearchX,
} from "lucide-react";

type MessageTone = "error" | "success" | "info";

const toneStyles: Record<MessageTone, string> = {
  error: "border-[#DA291C]/25 bg-red-50 text-red-800",
  success: "border-[#006747]/25 bg-[#F0F7F4] text-emerald-800",
  info: "border-[#002D62]/15 bg-[#EFF6FF] text-[#002D62]",
};

const toneIcons = {
  error: AlertCircle,
  success: CheckCircle2,
  info: Info,
};

export function PageLoading({
  label = "Loading NIERS",
}: {
  label?: string;
}) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200 px-4">
      <div className="w-full max-w-sm rounded-3xl border border-[#002D62]/10 bg-zinc-200 p-8 text-center shadow-lg shadow-[#002D62]/5">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[#002D62] text-white">
          <Loader2 className="h-7 w-7 animate-spin" aria-hidden />
        </div>
        <p className="mt-5 text-base font-semibold text-[#002D62]">{label}</p>
        <p className="mt-2 text-sm text-slate-600">
          Please wait while the latest information is prepared.
        </p>
      </div>
    </div>
  );
}

export function MessageBanner({
  tone,
  title,
  children,
  action,
  className = "",
}: {
  tone: MessageTone;
  title?: string;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  const Icon = toneIcons[tone];

  return (
    <div
      className={`rounded-2xl border p-4 text-sm ${toneStyles[tone]} ${className}`}
      role={tone === "error" ? "alert" : "status"}
    >
      <div className="flex gap-3">
        <Icon className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
        <div className="min-w-0 flex-1">
          {title ? <p className="font-semibold">{title}</p> : null}
          <div className={title ? "mt-1 leading-6" : "leading-6"}>
            {children}
          </div>
          {action ? <div className="mt-3 flex flex-wrap gap-2">{action}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action,
  className = "",
}: {
  title: string;
  description: string;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-3xl border border-dashed border-[#002D62]/20 bg-white p-8 text-center shadow-sm ${className}`}
    >
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-[#EFF6FF] text-[#002D62]">
        {icon ?? <SearchX className="h-6 w-6" aria-hidden />}
      </div>
      <h3 className="mt-4 font-semibold text-gray-900">{title}</h3>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-gray-600">
        {description}
      </p>
      {action ? <div className="mt-5 flex justify-center">{action}</div> : null}
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  meta,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="rounded-3xl border border-[#002D62]/10 bg-zinc-200 p-5 shadow-lg shadow-[#002D62]/5 sm:p-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          {eyebrow ? (
            <p className="text-sm font-semibold uppercase tracking-wide text-[#006747]">
              {eyebrow}
            </p>
          ) : null}
          <h1 className="mt-1 text-2xl font-bold text-[#002D62]">{title}</h1>
          {description ? (
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-700">
              {description}
            </p>
          ) : null}
          {meta ? <div className="mt-3">{meta}</div> : null}
        </div>
        {actions ? (
          <div className="flex shrink-0 flex-col gap-2 sm:flex-row sm:flex-wrap lg:justify-end">
            {actions}
          </div>
        ) : null}
      </div>
    </section>
  );
}
