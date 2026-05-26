import type { ReactNode } from "react";

const STATUS_STYLES: Record<string, string> = {
  received: "bg-[#EFF6FF] text-[#002D62] ring-[#002D62]/15",
  under_review: "bg-amber-50 text-amber-800 ring-amber-200",
  linked_to_case: "bg-[#E8F2FF] text-[#002D62] ring-[#002D62]/15",
  linked_to_incident: "bg-red-50 text-[#B71C1C] ring-[#DA291C]/20",
  escalated_to_emergency: "bg-red-50 text-[#B71C1C] ring-[#DA291C]/20",
  reported: "bg-red-50 text-[#B71C1C] ring-[#DA291C]/20",
  classified: "bg-amber-50 text-amber-800 ring-amber-200",
  agency_assigned: "bg-[#E8F2FF] text-[#002D62] ring-[#002D62]/15",
  unit_assigned: "bg-[#E8F2FF] text-[#002D62] ring-[#002D62]/15",
  dispatched: "bg-[#EFF6FF] text-[#002D62] ring-[#002D62]/15",
  in_progress: "bg-[#EFF6FF] text-[#002D62] ring-[#002D62]/15",
  resolved: "bg-[#F0F7F4] text-[#006747] ring-[#006747]/20",
  closed: "bg-slate-100 text-slate-700 ring-slate-200",
  cancelled: "bg-slate-100 text-slate-700 ring-slate-200",
  active: "bg-[#F0F7F4] text-[#006747] ring-[#006747]/20",
  inactive: "bg-slate-100 text-slate-700 ring-slate-200",
  suspended: "bg-amber-50 text-amber-800 ring-amber-200",
  blocked: "bg-red-50 text-[#B71C1C] ring-[#DA291C]/20",
  low: "bg-[#F0F7F4] text-[#006747] ring-[#006747]/20",
  medium: "bg-amber-50 text-amber-800 ring-amber-200",
  high: "bg-orange-50 text-orange-800 ring-orange-200",
  critical: "bg-red-50 text-[#B71C1C] ring-[#DA291C]/20",
  urgent: "bg-red-50 text-[#B71C1C] ring-[#DA291C]/20",
  emergency: "bg-red-50 text-[#B71C1C] ring-[#DA291C]/20",
  non_emergency: "bg-[#F0F7F4] text-[#006747] ring-[#006747]/20",
  unknown: "bg-amber-50 text-amber-800 ring-amber-200",
  false_alarm: "bg-slate-100 text-slate-700 ring-slate-200",
  duplicate_incident: "bg-slate-100 text-slate-700 ring-slate-200",
  transferred: "bg-[#EFF6FF] text-[#002D62] ring-[#002D62]/15",
  unresolved: "bg-amber-50 text-amber-800 ring-amber-200",
};

export function formatBadgeLabel(value: string | null | undefined) {
  return value ? value.replace(/_/g, " ") : "-";
}

export function Badge({
  children,
  tone,
}: {
  children: ReactNode;
  tone?: string | null;
}) {
  const style = tone ? STATUS_STYLES[tone] : undefined;

  return (
    <span
      className={`inline-flex max-w-full items-center rounded-full px-2.5 py-1 text-xs font-semibold capitalize ring-1 ${
        style ?? "bg-slate-100 text-slate-700 ring-slate-200"
      }`}
    >
      {children}
    </span>
  );
}
