import type { Gateway999IncidentOption } from "@/components/dispatcher/gateway-999/types";
import { formatIncidentCategory } from "@/lib/incident-status";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";

export function mapGateway999IncidentOption(
  row: OperationsIncidentRow,
): Gateway999IncidentOption | null {
  if (!row.public_uuid?.trim()) return null;

  const locationText =
    row.location?.address_text?.trim() ||
    row.location?.place_name?.trim() ||
    row.location_text?.trim() ||
    "No location recorded";

  return {
    publicUuid: row.public_uuid,
    incidentCode: row.incident_code?.trim() || "Unknown code",
    title: row.title?.trim() || "Untitled incident",
    categoryLabel: formatIncidentCategory(row.category_code),
    severity: row.severity_code?.trim() || "medium",
    status: row.status_code?.trim() || "classified",
    reportedAt: row.reported_at ?? "",
    locationText,
  };
}
