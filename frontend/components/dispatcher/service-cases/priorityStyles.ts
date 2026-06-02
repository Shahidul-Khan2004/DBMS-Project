const PRIORITY_CARD_ACCENT: Record<string, string> = {
  urgent: "border-l-4 border-l-[#B91C1C]/70",
  high: "border-l-4 border-l-orange-400/80",
  medium: "border-l-4 border-l-amber-300/90",
  low: "border-l-4 border-l-[#006747]/35",
};

const PRIORITY_BADGE_TONE: Record<string, string> = {
  urgent: "urgent",
  high: "high",
  medium: "medium",
  low: "low",
};

const DEFAULT_CARD_ACCENT = "border-l-4 border-l-slate-300/80";
const DEFAULT_BADGE_TONE = "medium";

export const SERVICE_CASE_COLUMN_COUNT_CLASSES =
  "bg-[#F0F7F4] text-[#006747] ring-1 ring-[#006747]/20";

export function getServiceCaseCardAccent(priority: string | null | undefined): string {
  const key = priority?.trim().toLowerCase();
  return (key && PRIORITY_CARD_ACCENT[key]) || DEFAULT_CARD_ACCENT;
}

export function getServiceCaseCardAccentMuted(priority: string | null | undefined): string {
  const accent = getServiceCaseCardAccent(priority);
  return accent
    .replace("/70", "/40")
    .replace("/80", "/40")
    .replace("/90", "/40")
    .replace("/35", "/25");
}

export function getServiceCasePriorityBadgeTone(
  priority: string | null | undefined,
): string {
  const key = priority?.trim().toLowerCase();
  return (key && PRIORITY_BADGE_TONE[key]) || DEFAULT_BADGE_TONE;
}

export function getServiceCaseColumnCountClasses(): string {
  return SERVICE_CASE_COLUMN_COUNT_CLASSES;
}
