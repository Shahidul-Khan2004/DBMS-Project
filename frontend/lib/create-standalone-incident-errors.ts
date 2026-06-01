import { ApiError } from "@/lib/api";

const ERROR_HINTS: Record<string, string> = {
  CATEGORY_REQUIRED: "Choose a category for the incident.",
  LOCATION_REQUIRED: "Select a confirmed incident location before creating.",
  INCIDENT_TITLE_REQUIRED: "Add a title for this incident.",
  INCIDENT_SEVERITY_NOT_FOUND: "Choose one of the supported severity levels.",
  REPORT_CATEGORY_NOT_FOUND: "Choose one of the supported incident categories.",
};

export function mapCreateStandaloneIncidentError(
  error: unknown,
  fallback = "Incident creation failed.",
): string {
  if (error instanceof ApiError) {
    const hint = error.code ? ERROR_HINTS[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}`;
  }

  return error instanceof Error ? error.message : fallback;
}
