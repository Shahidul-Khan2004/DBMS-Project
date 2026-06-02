import type { ReactNode } from "react";

const STATUS_STYLES: Record<string, string> = {
  received: "bg-[#EFF6FF] text-[#002D62] ring-[#002D62]/15",
  under_review: "bg-amber-50 text-amber-800 ring-amber-200",
  linked_to_case: "bg-[#E8F2FF] text-[#002D62] ring-[#002D62]/15",
  linked_to_incident: "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20",
  escalated_to_emergency: "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20",
  reported: "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20",
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
  blocked: "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20",
  low: "bg-[#F0F7F4] text-[#006747] ring-[#006747]/20",
  severity_low: "bg-slate-100 text-slate-700 ring-slate-200",
  submitted: "bg-[#EFF6FF] text-[#002D62] ring-[#002D62]/15",
  awaiting_user_response: "bg-amber-50 text-amber-800 ring-amber-200",
  no_action_needed: "bg-[#F0F7F4] text-[#006747] ring-[#006747]/20",
  medium: "bg-amber-50 text-amber-800 ring-amber-200",
  high: "bg-orange-50 text-orange-800 ring-orange-200",
  critical: "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20",
  urgent: "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20",
  emergency: "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20",
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

const BADGE_SIZE_STYLES = {
  default: "px-2.5 py-1 font-semibold",
  compact: "px-2 py-0.5 font-medium",
} as const;

export function Badge({
  children,
  tone,
  size = "default",
}: {
  children: ReactNode;
  tone?: string | null;
  size?: keyof typeof BADGE_SIZE_STYLES;
}) {
  const style = tone ? STATUS_STYLES[tone] : undefined;

  return (
    <span
      className={`inline-flex max-w-full items-center rounded-full text-xs capitalize ring-1 ${BADGE_SIZE_STYLES[size]} ${
        style ?? "bg-slate-100 text-slate-700 ring-slate-200"
      }`}
    >
      {children}
    </span>
  );
}
