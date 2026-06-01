import type {
  ActiveIncidentListItem,
  ActiveIncidentsDateFilter,
  ActiveIncidentsStatusFilter,
} from "@/components/dispatcher/incidents/types";

function reportedAtMs(item: ActiveIncidentListItem): number {
  const ms = new Date(item.reportedAt).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

function matchesDateFilter(
  item: ActiveIncidentListItem,
  dateFilter: ActiveIncidentsDateFilter,
): boolean {
  if (dateFilter === "all_dates") return true;

  const reportedMs = reportedAtMs(item);
  if (reportedMs === 0) return false;

  const now = Date.now();
  const windowMs =
    dateFilter === "last_24h" ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;

  return now - reportedMs <= windowMs;
}

export function filterActiveIncidents(
  items: ActiveIncidentListItem[],
  statusFilter: ActiveIncidentsStatusFilter,
  dateFilter: ActiveIncidentsDateFilter,
): ActiveIncidentListItem[] {
  if (statusFilter !== "active_incidents") {
    return items;
  }

  return items.filter((item) => matchesDateFilter(item, dateFilter));
}
