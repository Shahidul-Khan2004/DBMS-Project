import type { ActiveIncidentListItem } from "@/components/dispatcher/incidents/types";
import { formatIncidentCategory } from "@/lib/incident-status";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";

export function mapOperationsIncidentToActiveListItem(
  row: OperationsIncidentRow,
): ActiveIncidentListItem | null {
  if (!row.public_uuid?.trim()) return null;

  return {
    publicUuid: row.public_uuid,
    incidentCode: row.incident_code?.trim() || "Unknown code",
    title: row.title?.trim() || "Untitled incident",
    categoryLabel: formatIncidentCategory(row.category_code),
    severity: row.severity_code?.trim() || "medium",
    status: row.status_code?.trim() || "classified",
    reportedAt: row.reported_at ?? "",
  };
}
