import { ApiError } from "@/lib/api";

function getErrorCode(error: unknown): string | undefined {
  if (error instanceof ApiError) {
    return error.code;
  }
  return undefined;
}

export function mapAssignAgencyError(error: unknown): string {
  switch (getErrorCode(error)) {
    case "AGENCY_ALREADY_PARTICIPATING":
      return "This agency is already participating in the incident.";
    case "AGENCY_NOT_FOUND":
      return "The selected agency could not be found.";
    case "INCIDENT_NOT_FOUND":
      return "This incident could not be found.";
    default:
      return "Unable to assign agency. Try again.";
  }
}

export function mapCreateDispatchError(error: unknown): string {
  switch (getErrorCode(error)) {
    case "UNIT_NOT_AVAILABLE":
      return "This unit is no longer available. Choose another unit.";
    case "AGENCY_NOT_PARTICIPATING":
      return "This unit's agency is not participating in the incident.";
    case "DISPATCH_ALREADY_EXISTS":
      return "This unit is already assigned to this incident.";
    case "UNIT_NOT_FOUND":
      return "The selected unit could not be found.";
    case "INCIDENT_NOT_FOUND":
      return "This incident could not be found.";
    case "VALIDATION_ERROR":
      return "Unable to load or create dispatch because required information is invalid.";
    default:
      return "Unable to assign unit for dispatch. Try again.";
  }
}

export function mapUpdateDispatchStatusError(error: unknown): string {
  switch (getErrorCode(error)) {
    case "INVALID_STATUS_TRANSITION":
      return "This dispatch has already changed status. Refreshing current state.";
    case "INVALID_STATUS_CODE":
      return "This dispatch status action is not supported.";
    case "DISPATCH_NOT_FOUND":
      return "This dispatch could not be found.";
    default:
      return "Unable to update dispatch status. Try again.";
  }
}

export function shouldRefreshDetailAfterDispatchStatusError(error: unknown) {
  return getErrorCode(error) === "INVALID_STATUS_TRANSITION";
}

export function shouldRefreshAvailableUnitsAfterCreateDispatchError(
  error: unknown,
) {
  return getErrorCode(error) === "UNIT_NOT_AVAILABLE";
}

export type IncidentStatusAction = "resolve" | "close" | "cancel";

const INCIDENT_STATUS_GENERIC_ERRORS: Record<IncidentStatusAction, string> = {
  resolve: "Unable to resolve incident. Try again.",
  close: "Unable to close incident. Try again.",
  cancel: "Unable to cancel incident. Try again.",
};

const INCIDENT_STATUS_TRANSITION_ERRORS: Record<IncidentStatusAction, string> = {
  resolve:
    "This incident cannot be resolved from its current status. Refreshing current state.",
  close:
    "This incident cannot be closed from its current status. Refreshing current state.",
  cancel:
    "This incident cannot be cancelled from its current status. Refreshing current state.",
};

export function mapPatchIncidentStatusError(
  error: unknown,
  action: IncidentStatusAction,
): string {
  switch (getErrorCode(error)) {
    case "INVALID_STATUS_TRANSITION":
      return INCIDENT_STATUS_TRANSITION_ERRORS[action];
    case "INCIDENT_NOT_FOUND":
      return "This incident could not be found.";
    default:
      return INCIDENT_STATUS_GENERIC_ERRORS[action];
  }
}

export function shouldRefreshDetailAfterIncidentStatusError(error: unknown) {
  return getErrorCode(error) === "INVALID_STATUS_TRANSITION";
}

export function mapLinkReportToIncidentError(error: unknown): string {
  switch (getErrorCode(error)) {
    case "INTAKE_ALREADY_LINKED":
      return "This report is already linked to an incident.";
    case "EMERGENCY_INCIDENT_REQUIRES_LOCATION":
      return "This report must have a location before it can be linked.";
    case "INTAKE_REPORT_NOT_FOUND":
      return "This report could not be found.";
    case "INCIDENT_NOT_FOUND":
      return "This incident could not be found.";
    case "INCIDENT_NOT_LINKABLE":
      return "This incident cannot accept new intake links.";
    default:
      return "Unable to link this report.";
  }
}

export function mapResponseTimingLoadError(error: unknown): string {
  switch (getErrorCode(error)) {
    case "INCIDENT_NOT_FOUND":
      return "Response timing could not be loaded because this incident was not found.";
    default:
      return "Unable to load response timing.";
  }
}
