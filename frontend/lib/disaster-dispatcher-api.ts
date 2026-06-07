import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import {
  fetchAllPendingIntakeReports,
  getOperationsIncidents,
  linkIntakeToIncident,
  promoteIntakeToEmergencyIncident,
  TERMINAL_INCIDENT_STATUSES,
  LINKABLE_INCIDENT_STATUSES,
  type LinkIntakeToIncidentPayload,
  type OperationsIncidentRow,
  type PromoteEmergencyPayload,
} from "@/lib/operations-intake-triage";
import type { OperationsIntakeReport } from "@/types/operations-intake";

export {
  linkIncidentToDisaster,
  listOperationsDisasters,
  getOperationsDisaster,
} from "@/lib/disaster-operations-api";

export {
  promoteIntakeToEmergencyIncident as promoteIntakeReportToEmergency,
  linkIntakeToIncident as linkIntakeReportToIncident,
  type PromoteEmergencyPayload,
  type LinkIntakeToIncidentPayload,
};

export type CandidateDisasterReport = OperationsIntakeReport & {
  affectedAreaMatch: boolean;
};

export type CandidateDisasterReportsResult = {
  affectedAreaMatches: CandidateDisasterReport[];
  allPending: CandidateDisasterReport[];
};

function getAffectedAreaAdminIds(
  dashboard: OperationsDisasterDashboard,
): Set<number> {
  const ids = new Set<number>();
  for (const area of dashboard.affected_areas ?? []) {
    if (area.admin_area_id != null) {
      ids.add(area.admin_area_id);
    }
  }
  return ids;
}

function isReportAffectedAreaMatch(
  report: OperationsIntakeReport,
  affectedAreaIds: Set<number>,
): boolean {
  const adminAreaId = report.location?.admin_area_id;
  if (adminAreaId == null || affectedAreaIds.size === 0) return false;
  return affectedAreaIds.has(adminAreaId);
}

export async function listCandidateDisasterReports(
  dashboard: OperationsDisasterDashboard,
): Promise<CandidateDisasterReportsResult> {
  const reports = await fetchAllPendingIntakeReports({
    statusFilter: "all",
    categoryFilter: "all",
    sortOrder: "newest",
    limit: 100,
    offset: 0,
  });

  const pending = reports.filter((report) => !report.has_incident);
  const affectedAreaIds = getAffectedAreaAdminIds(dashboard);

  const withMatch: CandidateDisasterReport[] = pending.map((report) => ({
    ...report,
    affectedAreaMatch: isReportAffectedAreaMatch(report, affectedAreaIds),
  }));

  const affectedAreaMatches = withMatch.filter((report) => report.affectedAreaMatch);
  const allPending = withMatch;

  return { affectedAreaMatches, allPending };
}

export async function listCandidateDisasterIncidents(
  dashboard: OperationsDisasterDashboard,
): Promise<OperationsIncidentRow[]> {
  const linkedUuids = new Set(
    (dashboard.linked_incidents ?? [])
      .map((incident) => incident.incident_public_uuid)
      .filter(Boolean),
  );

  const data = await getOperationsIncidents({ limit: 100, offset: 0 });
  const incidents = data.incidents ?? [];

  return incidents.filter((incident) => {
    if (linkedUuids.has(incident.public_uuid)) return false;
    if (TERMINAL_INCIDENT_STATUSES.has(incident.status_code)) return false;
    return true;
  });
}

export function sortIncidentsByAffectedAreaMatch(
  incidents: OperationsIncidentRow[],
  dashboard: OperationsDisasterDashboard,
): OperationsIncidentRow[] {
  if (getAffectedAreaAdminIds(dashboard).size === 0) return incidents;

  return [...incidents].sort((a, b) => {
    const aActive = LINKABLE_INCIDENT_STATUSES.has(a.status_code) ? 0 : 1;
    const bActive = LINKABLE_INCIDENT_STATUSES.has(b.status_code) ? 0 : 1;
    if (aActive !== bActive) return aActive - bActive;
    return 0;
  });
}
