import type { ActiveIncidentListItem } from "@/components/dispatcher/incidents/types";

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const DEFAULT_SEVERITY_RANK = 4;

function severityRank(severity: string): number {
  const key = severity?.trim().toLowerCase();
  return key && key in SEVERITY_RANK ? SEVERITY_RANK[key]! : DEFAULT_SEVERITY_RANK;
}

function reportedAtMs(item: ActiveIncidentListItem): number {
  const ms = new Date(item.reportedAt).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

export function sortActiveIncidents(
  items: ActiveIncidentListItem[],
): ActiveIncidentListItem[] {
  return [...items].sort((a, b) => {
    const rankDiff = severityRank(a.severity) - severityRank(b.severity);
    if (rankDiff !== 0) return rankDiff;
    return reportedAtMs(b) - reportedAtMs(a);
  });
}
