import { formatRelativeAge } from "@/lib/format-relative-age";
import { isTerminalDispatch } from "@/lib/agency-dispatch-utils";
import type { AgencyDispatch, AgencyIncident, AgencyUnit } from "@/types/agency";

const DISPATCH_PRIORITY_RANK: Record<string, number> = {
  critical: 0,
  urgent: 1,
  high: 2,
  medium: 3,
  low: 4,
};

const ACTIVE_DISPATCH_STATUSES = new Set(["assigned", "dispatched", "arrived"]);

function getDispatchPriorityRank(priority: string | null | undefined): number {
  if (!priority) return 99;
  return DISPATCH_PRIORITY_RANK[priority.toLowerCase()] ?? 99;
}

function getDispatchLatestTimestamp(dispatch: AgencyDispatch): string | null {
  return (
    dispatch.cancelled_at ??
    dispatch.completed_at ??
    dispatch.arrived_at ??
    dispatch.dispatched_at ??
    dispatch.assigned_at
  );
}

export type GroupedAgencyIncident = {
  incidentPublicUuid: string;
  title: string;
  incidentCode: string;
  statusCode: string | null;
  participationStatus: string | null;
  highestPriority: string | null;
  assignedUnitCount: number;
  latestUpdateAt: string | null;
  dispatches: AgencyDispatch[];
};

function isUuidLikeTitle(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return true;
  if (/^EMI-[A-Z0-9-]+$/i.test(trimmed)) return true;
  if (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)
  ) {
    return true;
  }
  return false;
}

export function getIncidentDisplayTitle(
  dispatch: AgencyDispatch | undefined,
  incidentCode?: string | null,
): string {
  const title = dispatch?.incident.title?.trim();
  if (title && !isUuidLikeTitle(title)) return title;
  return "Emergency Incident";
}

export function groupDispatchesByIncident(
  dispatches: AgencyDispatch[],
  incidents: AgencyIncident[] = [],
): GroupedAgencyIncident[] {
  const incidentMeta = new Map(
    incidents.map((incident) => [incident.incident_public_uuid, incident]),
  );
  const groups = new Map<string, AgencyDispatch[]>();

  for (const dispatch of dispatches) {
    const key = dispatch.incident.public_uuid;
    const existing = groups.get(key) ?? [];
    existing.push(dispatch);
    groups.set(key, existing);
  }

  const grouped: GroupedAgencyIncident[] = [];

  for (const [incidentPublicUuid, incidentDispatches] of groups) {
    const meta = incidentMeta.get(incidentPublicUuid);
    const sample = incidentDispatches[0];
    const incidentCode =
      meta?.incident_code ?? sample?.incident.incident_code ?? "—";

    let highestPriority: string | null = null;
    let highestRank = 99;
    let latestUpdateAt: string | null = null;

    for (const dispatch of incidentDispatches) {
      const rank = getDispatchPriorityRank(dispatch.priority_level);
      if (rank < highestRank) {
        highestRank = rank;
        highestPriority = dispatch.priority_level;
      }
      const timestamp = getDispatchLatestTimestamp(dispatch);
      if (timestamp && (!latestUpdateAt || timestamp > latestUpdateAt)) {
        latestUpdateAt = timestamp;
      }
    }

    grouped.push({
      incidentPublicUuid,
      title: getIncidentDisplayTitle(sample, incidentCode),
      incidentCode,
      statusCode: meta?.status_code ?? null,
      participationStatus: meta?.participation_status ?? null,
      highestPriority,
      assignedUnitCount: incidentDispatches.length,
      latestUpdateAt,
      dispatches: incidentDispatches,
    });
  }

  return grouped.sort((a, b) => {
    const aActive = a.dispatches.some((d) => ACTIVE_DISPATCH_STATUSES.has(d.status_code));
    const bActive = b.dispatches.some((d) => ACTIVE_DISPATCH_STATUSES.has(d.status_code));
    if (aActive !== bActive) return aActive ? -1 : 1;

    const priorityDiff =
      getDispatchPriorityRank(a.highestPriority) - getDispatchPriorityRank(b.highestPriority);
    if (priorityDiff !== 0) return priorityDiff;

    const aTime = a.latestUpdateAt ?? "";
    const bTime = b.latestUpdateAt ?? "";
    return bTime.localeCompare(aTime);
  });
}

export function selectDefaultIncidentUuid(
  grouped: GroupedAgencyIncident[],
): string | null {
  if (grouped.length === 0) return null;

  const withActive = grouped.filter((group) =>
    group.dispatches.some((d) => ACTIVE_DISPATCH_STATUSES.has(d.status_code)),
  );

  const pool = withActive.length > 0 ? withActive : grouped;
  return pool[0]?.incidentPublicUuid ?? null;
}

export function getIncidentLatestUpdateLabel(
  latestUpdateAt: string | null,
): string {
  if (!latestUpdateAt) return "—";
  return formatRelativeAge(latestUpdateAt);
}

export function countAvailableUnits(
  units: Array<{ is_active: boolean; status_code: string }>,
): number {
  return units.filter((u) => u.is_active && u.status_code === "available").length;
}

export function countBusyUnits(
  units: Array<{ is_active: boolean; status_code: string }>,
): number {
  return units.filter((u) => u.is_active && u.status_code === "busy").length;
}

export function getDispatchStatusSummary(dispatches: AgencyDispatch[]): string {
  const counts = new Map<string, number>();
  for (const dispatch of dispatches) {
    counts.set(dispatch.status_code, (counts.get(dispatch.status_code) ?? 0) + 1);
  }
  const parts = [...counts.entries()].map(([status, count]) => `${count} ${status}`);
  return parts.length > 0 ? parts.join(", ") : "—";
}

export function hasActiveIncidentWork(dispatches: AgencyDispatch[]): boolean {
  return dispatches.some((d) => !isTerminalDispatch(d.status_code));
}

export function getUnitTypeForDispatch(
  dispatch: AgencyDispatch,
  units: AgencyUnit[],
): string | null {
  const match = units.find((unit) => unit.public_uuid === dispatch.unit.public_uuid);
  return match?.unit_type_code ?? null;
}
