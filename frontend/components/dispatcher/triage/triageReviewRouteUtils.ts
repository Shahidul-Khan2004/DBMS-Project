import {
  createEmergencyDraft,
  createLinkDraft,
  createServiceCaseDraft,
} from "@/components/dispatcher/triage/draftDefaults";
import type {
  ActiveIncidentOption,
  EmergencySeverity,
  IntakeQueueItem,
  RouteMode,
  ServiceCasePriority,
} from "@/components/dispatcher/triage/types";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { formatRelativeAge } from "@/lib/format-relative-age";
import {
  LINKABLE_INCIDENT_STATUSES,
  TERMINAL_INCIDENT_STATUSES,
  type OperationsIncidentRow,
} from "@/lib/operations-intake-triage";

export function resetDraftsForItem(item: IntakeQueueItem) {
  return {
    serviceCaseDraft: createServiceCaseDraft(item),
    emergencyDraft: createEmergencyDraft(item),
    linkDraft: createLinkDraft(),
  };
}

export type RouteChoice = Extract<
  RouteMode,
  | "service_case"
  | "emergency_incident"
  | "existing_incident"
  | "duplicate"
  | "false_report"
>;

export function isSuccessRouteMode(mode: RouteMode): boolean {
  return (
    mode === "success_service_case" ||
    mode === "success_emergency_incident" ||
    mode === "success_existing_incident" ||
    mode === "success_duplicate" ||
    mode === "success_false_report"
  );
}

const SERVICE_CASE_PRIORITIES: ServiceCasePriority[] = [
  "low",
  "medium",
  "high",
  "urgent",
];

export function parseServiceCasePriority(
  value: string | null | undefined,
  fallback: ServiceCasePriority,
): ServiceCasePriority {
  if (value && SERVICE_CASE_PRIORITIES.includes(value as ServiceCasePriority)) {
    return value as ServiceCasePriority;
  }
  return fallback;
}

const EMERGENCY_SEVERITIES: EmergencySeverity[] = [
  "low",
  "medium",
  "high",
  "critical",
];

export function parseEmergencySeverity(
  value: string | null | undefined,
  fallback: EmergencySeverity,
): EmergencySeverity {
  if (value && EMERGENCY_SEVERITIES.includes(value as EmergencySeverity)) {
    return value as EmergencySeverity;
  }
  return fallback;
}

export function mapIncidentToOption(
  incident: OperationsIncidentRow,
): ActiveIncidentOption | null {
  if (
    TERMINAL_INCIDENT_STATUSES.has(incident.status_code) ||
    !LINKABLE_INCIDENT_STATUSES.has(incident.status_code)
  ) {
    return null;
  }

  const locationFromApi =
    incident.location?.address_text?.trim() ||
    incident.location?.place_name?.trim() ||
    incident.location_text?.trim() ||
    "";

  return {
    id: incident.public_uuid,
    incidentCode: incident.incident_code?.trim() || "Unknown code",
    title: incident.title?.trim() || "Untitled incident",
    categoryLabel: incident.category_code
      ? formatBadgeLabel(incident.category_code)
      : undefined,
    locationText: locationFromApi || "Location unavailable",
    statusLabel: formatBadgeLabel(incident.status_code),
    severityLabel: incident.severity_code
      ? formatBadgeLabel(incident.severity_code)
      : undefined,
    reportedAgeLabel: incident.reported_at
      ? formatRelativeAge(incident.reported_at)
      : undefined,
  };
}
