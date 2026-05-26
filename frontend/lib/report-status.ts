import type { IntakeReport } from "@/types/intake";
import type { CitizenServiceCase } from "@/types/service-case";

export const INTAKE_PENDING_STATUSES = new Set(["received", "under_review"]);

export const INTAKE_LINKED_STATUSES = new Set([
  "linked_to_case",
  "linked_to_incident",
]);

export const INTAKE_FINAL_STATUSES = new Set([
  "resolved",
  "closed",
  "cancelled",
  "duplicate",
  "false_report",
]);

export const SERVICE_CASE_OPEN_STATUSES = new Set([
  "submitted",
  "under_review",
  "awaiting_user_response",
]);

export const SERVICE_CASE_FINAL_STATUSES = new Set([
  "resolved",
  "closed",
  "cancelled",
  "escalated_to_emergency",
]);

const INCIDENT_FINAL_STATUSES = new Set(["resolved", "closed", "cancelled"]);

const REPORT_STATUS_LABELS: Record<string, string> = {
  received: "Received",
  under_review: "Under Review",
  linked_to_case: "Linked To Service Case",
  linked_to_incident: "Linked To Incident",
  resolved: "Resolved",
  closed: "Closed",
  cancelled: "Cancelled",
  duplicate: "Duplicate",
  false_report: "False Report",
};

export function formatReportStatus(status: string | null | undefined) {
  if (!status) return "-";
  return (
    REPORT_STATUS_LABELS[status] ??
    status
      .split("_")
      .filter(Boolean)
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(" ")
  );
}

export function getReportStatusTone(status: string | null | undefined) {
  if (!status) return "unknown";
  return status;
}

export function isPendingReport(report: IntakeReport) {
  return INTAKE_PENDING_STATUSES.has(report.intake_status);
}

export function mapServiceCasesByIntakeUuid(serviceCases: CitizenServiceCase[]) {
  const serviceCasesByIntakeUuid = new Map<string, CitizenServiceCase[]>();

  for (const serviceCase of serviceCases) {
    if (!serviceCase.intake_public_uuid) continue;

    const current = serviceCasesByIntakeUuid.get(serviceCase.intake_public_uuid) ?? [];
    current.push(serviceCase);
    serviceCasesByIntakeUuid.set(serviceCase.intake_public_uuid, current);
  }

  return serviceCasesByIntakeUuid;
}

function hasLinkedServiceCaseStatus(
  report: IntakeReport,
  serviceCasesByIntakeUuid: Map<string, CitizenServiceCase[]>,
  statuses: Set<string>,
) {
  const serviceCases = serviceCasesByIntakeUuid.get(report.public_uuid) ?? [];
  return serviceCases.some((serviceCase) => {
    const statusCode = serviceCase.status_code;
    return statusCode != null && statuses.has(statusCode);
  });
}

export function isFinalReportOrLinkedResolved(
  report: IntakeReport,
  serviceCasesByIntakeUuid: Map<string, CitizenServiceCase[]>,
) {
  if (INTAKE_FINAL_STATUSES.has(report.intake_status)) return true;

  if (report.intake_status === "linked_to_case") {
    return hasLinkedServiceCaseStatus(
      report,
      serviceCasesByIntakeUuid,
      SERVICE_CASE_FINAL_STATUSES,
    );
  }

  if (report.intake_status === "linked_to_incident") {
    const incidentStatus = report.incident_status_code;
    return incidentStatus != null && INCIDENT_FINAL_STATUSES.has(incidentStatus);
  }

  return false;
}
