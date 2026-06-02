import { formatRelativeAge } from "@/lib/format-relative-age";
import type {
  AgencyDispatch,
  AgencyDispatchStatusAction,
  AgencyDispatchStatusCode,
} from "@/types/agency";

const TERMINAL_STATUSES = new Set<AgencyDispatchStatusCode>([
  "completed",
  "cancelled",
]);

const STATUS_PRIORITY: AgencyDispatchStatusCode[] = [
  "assigned",
  "dispatched",
  "arrived",
];

export function isTerminalDispatch(status: string): boolean {
  return TERMINAL_STATUSES.has(status as AgencyDispatchStatusCode);
}

export function getNextDispatchAction(
  statusCode: string,
): AgencyDispatchStatusAction | null {
  switch (statusCode) {
    case "assigned":
      return "dispatched";
    case "dispatched":
      return "arrived";
    case "arrived":
      return "completed";
    default:
      return null;
  }
}

export function canCancelDispatch(statusCode: string): boolean {
  return (
    statusCode === "assigned" ||
    statusCode === "dispatched" ||
    statusCode === "arrived"
  );
}

export function getDispatchActionLabel(
  action: AgencyDispatchStatusAction,
): string {
  switch (action) {
    case "dispatched":
      return "Mark Dispatched";
    case "arrived":
      return "Mark Arrived";
    case "completed":
      return "Mark Completed";
    case "cancelled":
      return "Cancel Dispatch";
    default:
      return "Update Status";
  }
}

export function getDispatchConfirmTitle(
  action: AgencyDispatchStatusAction,
): string {
  switch (action) {
    case "dispatched":
      return "Mark unit as dispatched?";
    case "arrived":
      return "Mark unit as arrived?";
    case "completed":
      return "Mark dispatch as completed?";
    case "cancelled":
      return "Cancel dispatch?";
    default:
      return "Update dispatch status?";
  }
}

export function selectDefaultDispatch(
  dispatches: AgencyDispatch[],
): AgencyDispatch | null {
  if (dispatches.length === 0) return null;

  for (const status of STATUS_PRIORITY) {
    const match = dispatches.find((d) => d.status_code === status);
    if (match) return match;
  }

  const nonTerminal = dispatches.filter((d) => !isTerminalDispatch(d.status_code));
  if (nonTerminal.length > 0) {
    return [...nonTerminal].sort((a, b) => {
      const aTime = a.assigned_at ?? "";
      const bTime = b.assigned_at ?? "";
      return bTime.localeCompare(aTime);
    })[0];
  }

  return dispatches[0];
}

export function getDispatchAgeLabel(dispatch: AgencyDispatch): string {
  const timestamp =
    dispatch.cancelled_at ??
    dispatch.completed_at ??
    dispatch.arrived_at ??
    dispatch.dispatched_at ??
    dispatch.assigned_at;

  if (!timestamp) return "—";
  return formatRelativeAge(timestamp);
}

export function formatAgencyTypeLabel(typeCode: string | null | undefined): string {
  if (!typeCode) return "—";
  return typeCode
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

export function formatReadableLabel(value: string | null | undefined): string {
  if (!value) return "—";
  return value
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

export function filterDispatchesByStatus(
  dispatches: AgencyDispatch[],
  filter: string,
): AgencyDispatch[] {
  if (filter === "all") return dispatches;
  return dispatches.filter((d) => d.status_code === filter);
}

export function filterDispatchesByIncident(
  dispatches: AgencyDispatch[],
  incidentPublicUuid: string,
): AgencyDispatch[] {
  return dispatches.filter(
    (d) => d.incident.public_uuid === incidentPublicUuid,
  );
}
