import type { CitizenIncident } from "@/types/citizen-incident";

export const ACTIVE_INCIDENT_STATUSES = new Set([
  "reported",
  "classified",
  "agency_assigned",
  "unit_assigned",
  "dispatched",
  "in_progress",
]);

export const FINAL_INCIDENT_STATUSES = new Set([
  "resolved",
  "closed",
  "cancelled",
]);

const INCIDENT_CATEGORY_LABELS: Record<string, string> = {
  crime_public_safety: "Crime / Public Safety",
  infrastructure_emergency: "Infrastructure Emergency",
  natural_disaster: "Natural Disaster",
};

function titleCaseFromSnake(value: string) {
  return value
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

export function formatIncidentCategory(categoryCode: string | null | undefined) {
  if (!categoryCode?.trim()) return "-";
  const key = categoryCode.trim().toLowerCase();
  return INCIDENT_CATEGORY_LABELS[key] ?? titleCaseFromSnake(key);
}

const INCIDENT_STATUS_LABELS: Record<string, string> = {
  reported: "Reported",
  classified: "Classified",
  agency_assigned: "Agency Assigned",
  unit_assigned: "Unit Assigned",
  dispatched: "Dispatched",
  in_progress: "In Progress",
  resolved: "Resolved",
  closed: "Closed",
  cancelled: "Cancelled",
};

export function formatIncidentStatus(status: string | null | undefined) {
  if (!status) return "-";
  return (
    INCIDENT_STATUS_LABELS[status] ??
    status
      .split("_")
      .filter(Boolean)
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(" ")
  );
}

export function formatIncidentStatusContext(status: string | null | undefined) {
  const label = formatIncidentStatus(status);
  return label === "-" ? "Incident Status Unknown" : `Incident ${label}`;
}

export function isActiveIncident(incident: CitizenIncident) {
  return ACTIVE_INCIDENT_STATUSES.has(incident.status_code);
}

export function isFinalIncident(incident: CitizenIncident) {
  return FINAL_INCIDENT_STATUSES.has(incident.status_code);
}

export function isTerminalIncident(status: string | null | undefined) {
  if (!status) return false;
  return FINAL_INCIDENT_STATUSES.has(status);
}

export function isResolvedIncident(incident: CitizenIncident) {
  return incident.status_code === "resolved";
}

export function mapIncidentsByIntakeUuid(incidents: CitizenIncident[]) {
  const incidentsByIntakeUuid = new Map<string, CitizenIncident>();

  for (const incident of incidents) {
    if (!incident.intake_public_uuid) continue;
    incidentsByIntakeUuid.set(incident.intake_public_uuid, incident);
  }

  return incidentsByIntakeUuid;
}
