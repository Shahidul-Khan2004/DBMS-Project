import { FINAL_INCIDENT_STATUSES } from "@/lib/incident-status";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";

/**
 * Client-side active filter until backend supports `active_only`.
 * Excludes terminal incidents from operations list responses.
 */
export function filterNonTerminalOperationsIncidents(
  incidents: OperationsIncidentRow[],
): OperationsIncidentRow[] {
  return incidents.filter(
    (incident) => !FINAL_INCIDENT_STATUSES.has(incident.status_code),
  );
}
