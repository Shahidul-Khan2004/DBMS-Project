import { ApiError } from "@/lib/api";

function getErrorCode(error: unknown): string | undefined {
  if (error instanceof ApiError) {
    return error.code;
  }
  return undefined;
}

export function mapAgencyAccessError(error: unknown): string {
  const code = getErrorCode(error);
  if (error instanceof ApiError && error.status === 403) {
    return "Your agency access is inactive or unavailable.";
  }
  if (
    code === "MEMBERSHIP_INACTIVE" ||
    code === "FORBIDDEN" ||
    code === "MULTIPLE_AGENCY_MEMBERSHIPS"
  ) {
    return "Your agency access is inactive or unavailable.";
  }
  return "Unable to load agency workspace. Please try again.";
}

export function mapAgencyIncidentError(error: unknown): string {
  if (getErrorCode(error) === "INCIDENT_NOT_IN_AGENCY") {
    return "This incident is not available to your agency.";
  }
  if (error instanceof ApiError && error.status === 404) {
    return "This incident is not available to your agency.";
  }
  return "Unable to load incident details. Please try again.";
}

export function mapAgencyDeactivateUnitError(error: unknown): string {
  if (getErrorCode(error) === "UNIT_HAS_ACTIVE_DISPATCH") {
    return "This unit cannot be deactivated while it has an active dispatch.";
  }
  return "Unable to deactivate unit. Please try again.";
}

export function mapAgencyCreateUnitError(error: unknown): string {
  const code = getErrorCode(error);
  if (code === "UNIT_CODE_CONFLICT") {
    return "A unit with this code already exists for your agency.";
  }
  return "Unable to create unit. Please try again.";
}

export function mapAgencyUpdateUnitError(error: unknown): string {
  const code = getErrorCode(error);
  if (code === "UNIT_CODE_CONFLICT") {
    return "A unit with this code already exists for your agency.";
  }
  if (code === "UNIT_NOT_FOUND") {
    return "This unit could not be found.";
  }
  return "Unable to update unit. Please try again.";
}

export function mapAgencyUnitStatusError(error: unknown): string {
  const code = getErrorCode(error);
  if (code === "UNIT_NOT_FOUND") {
    return "This unit could not be found.";
  }
  if (code === "INVALID_STATUS_TRANSITION") {
    return "This unit status cannot be changed right now.";
  }
  return "Unable to update unit status. Please try again.";
}

export function mapAgencyResponseLogError(error: unknown): string {
  const code = getErrorCode(error);
  if (code === "INCIDENT_NOT_IN_AGENCY") {
    return "This incident is not available to your agency.";
  }
  if (code === "RESPONSE_LOG_DISPATCH_MISMATCH") {
    return "The selected dispatch is not linked to this incident.";
  }
  return "Unable to save field update. Please try again.";
}
