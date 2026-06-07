/** Dispatcher emergency / danger palette — deeper red for operational UI. */
export const DISPATCHER_EMERGENCY = {
  default: "#B91C1C",
  hover: "#991B1B",
  active: "#7F1D1D",
  bg: "#FEF2F2",
  text: "#991B1B",
} as const;

export const DISPATCHER_EMERGENCY_BADGE_CLASSES =
  "bg-[#FEF2F2] text-[#991B1B] ring-[#B91C1C]/20";

export const DISPATCHER_EMERGENCY_ALERT_PANEL_CLASSES =
  "border-[#B91C1C]/25 bg-[#FEF2F2]";

export const DISPATCHER_EMERGENCY_ACTIVE_RING_CLASSES =
  "ring-2 ring-[#B91C1C]/30 ring-offset-1";

export function getEmergencyPrimaryLinkClasses(active = false): string {
  return [
    "inline-flex shrink-0 cursor-pointer items-center rounded-md border border-[#B91C1C] bg-[#B91C1C] px-3 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:border-[#991B1B] hover:bg-[#991B1B]",
    active ? DISPATCHER_EMERGENCY_ACTIVE_RING_CLASSES : "",
  ]
    .filter(Boolean)
    .join(" ");
}
