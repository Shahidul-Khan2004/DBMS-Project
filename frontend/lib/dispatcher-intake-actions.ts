import type { OperationsIntakeReport } from "@/types/operations-intake";

const INTAKE_CLASSIFIABLE_STATUSES = new Set(["received", "under_review"]);
const INTAKE_TERMINAL_STATUSES = new Set([
  "resolved",
  "closed",
  "cancelled",
  "duplicate",
  "false_report",
]);

export function getCreateIncidentHref(reportPublicUuid: string) {
  const query = new URLSearchParams({
    mode: "intake",
    intakeReportPublicUuid: reportPublicUuid,
  });

  return `/dashboard/dispatcher/incidents/create-incident?${query.toString()}`;
}

export function getEmergencyAction(report: OperationsIntakeReport) {
  const isEmergencyCall = report.channel_code === "emergency_call";

  return {
    href: isEmergencyCall
      ? `/dashboard/dispatcher/intake-reports/${report.public_uuid}/classify/emergency`
      : `/dashboard/dispatcher/intake-reports/${report.public_uuid}/promote/emergency`,
    label: isEmergencyCall ? "Classify Emergency Call" : "Promote to Emergency",
  };
}

export function getEscalateServiceCaseHref(reportPublicUuid: string) {
  return `/dashboard/dispatcher/intake-reports/${reportPublicUuid}/escalate/emergency`;
}

export function canCreateIncident(report: OperationsIntakeReport) {
  return (
    !report.has_incident &&
    !report.has_service_case &&
    INTAKE_CLASSIFIABLE_STATUSES.has(report.intake_status)
  );
}

export function canClassifyServiceCase(report: OperationsIntakeReport) {
  return canCreateIncident(report);
}

export function canPromoteEmergency(report: OperationsIntakeReport) {
  return canCreateIncident(report);
}

export function canEscalateServiceCase(report: OperationsIntakeReport) {
  return (
    report.has_service_case &&
    !report.has_incident &&
    report.intake_status === "linked_to_case" &&
    !INTAKE_TERMINAL_STATUSES.has(report.intake_status)
  );
}
