import { ApiError } from "@/lib/api";

export const ONBOARD_AGENCY_VALIDATION_MESSAGE =
  "Agency details could not be validated. Check required fields and selected location.";

function formatValidationDetails(details: unknown): string {
  if (!Array.isArray(details) || details.length === 0) {
    return "";
  }

  const formatted = details
    .map((detail) => {
      if (typeof detail === "string") return detail;
      if (detail && typeof detail === "object") {
        const entry = detail as { field?: string; message?: string };
        if (entry.field && entry.message) {
          return `${entry.field}: ${entry.message}`;
        }
        if (entry.message) return entry.message;
        return JSON.stringify(detail);
      }
      return String(detail);
    })
    .join("; ");

  return formatted ? ` Details: ${formatted}` : "";
}

export function formatOnboardAgencyValidationDetail(error: ApiError): string {
  const parts = [error.code, error.message].filter(Boolean);
  const base = parts.join(" · ");
  return `${base}${formatValidationDetails(error.details)}`;
}

export function formatAdminAgencyError(error: unknown): string {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      USER_NOT_FOUND: "No user was found for that public UUID.",
      AGENCY_CODE_CONFLICT:
        "That agency code is already in use. Choose a different code.",
      USER_ALREADY_REPRESENTATIVE:
        "That user is already a representative for this agency.",
      AGENCY_NOT_FOUND: "No agency was found for that identifier.",
      VALIDATION_ERROR:
        "Check the form fields and try again.",
    };

    const hint = error.code ? hints[error.code] : undefined;
    return `${error.code ? `${error.code}: ` : ""}${error.message}${
      hint ? ` ${hint}` : ""
    }`;
  }

  return error instanceof Error ? error.message : "Agency action failed.";
}

export { UUID_PATTERN } from "@/lib/admin-role-errors";
