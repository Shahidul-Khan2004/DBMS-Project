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

export function isServiceCaseOpen(statusCode: string | null | undefined) {
  return Boolean(statusCode && SERVICE_CASE_OPEN_STATUSES.has(statusCode));
}

export function isServiceCaseFinal(statusCode: string | null | undefined) {
  return Boolean(statusCode && SERVICE_CASE_FINAL_STATUSES.has(statusCode));
}

export function isServiceCaseEscalated(statusCode: string | null | undefined) {
  return statusCode === "escalated_to_emergency";
}

export function getServiceCaseStatusLabel(statusCode: string | null | undefined) {
  if (statusCode === "escalated_to_emergency") {
    return "Escalated to Emergency";
  }
  return statusCode ? statusCode.replace(/_/g, " ") : "-";
}
