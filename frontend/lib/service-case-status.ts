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
  if (!statusCode) return "-";
  if (statusCode === "escalated_to_emergency") {
    return "Escalated to Emergency";
  }
  if (statusCode === "awaiting_user_response") {
    return "Awaiting User Response";
  }
  if (statusCode === "under_review") {
    return "Under Review";
  }
  if (statusCode === "no_action_needed") {
    return "No Action Needed";
  }
  return statusCode
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}
