const SEVERITY_CARD_ACCENT: Record<string, string> = {
  critical: "border-l-4 border-l-[#B91C1C]/70",
  high: "border-l-4 border-l-orange-400/80",
  medium: "border-l-4 border-l-amber-300/90",
  low: "border-l-4 border-l-slate-300/90",
};

const SEVERITY_BADGE_TONE: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "severity_low",
};

const DEFAULT_CARD_ACCENT = "border-l-4 border-l-slate-300/80";
const DEFAULT_BADGE_TONE = "medium";

export function getSeverityCardAccent(severity: string): string {
  const key = severity?.trim().toLowerCase();
  return (key && SEVERITY_CARD_ACCENT[key]) || DEFAULT_CARD_ACCENT;
}

export function getSeverityBadgeTone(severity: string): string {
  const key = severity?.trim().toLowerCase();
  return (key && SEVERITY_BADGE_TONE[key]) || DEFAULT_BADGE_TONE;
}

export function getSeverityCardAccentMuted(severity: string): string {
  const accent = getSeverityCardAccent(severity);
  return accent
    .replace("/70", "/40")
    .replace("/80", "/40")
    .replace("/90", "/40");
}
