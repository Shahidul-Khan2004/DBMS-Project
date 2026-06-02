import { ApiError, apiGet, apiPatch, apiPost } from "@/lib/api";
import { sortNewestFirst, sortOldestFirst } from "@/lib/sort";
import type {
  IntakeLocationHistoryResponse,
  IntakeStructuredLocation,
  UpdateIntakeLocationResponse,
} from "@/types/intake";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportResponse,
  OperationsIntakeReportsResponse,
} from "@/types/operations-intake";
import type { DispatcherOverviewResponse } from "@/types/operations-overview";
import type {
  TriageCategoryFilter,
  TriageSortOrder,
  TriageStatusFilter,
} from "@/components/dispatcher/triage/types";

const DEFAULT_LIMIT = 50;
const DEFAULT_OFFSET = 0;
const INCIDENTS_DEFAULT_LIMIT = 100;

export const TERMINAL_INCIDENT_STATUSES = new Set([
  "resolved",
  "closed",
  "cancelled",
]);

export const LINKABLE_INCIDENT_STATUSES = new Set([
  "reported",
  "classified",
  "in_progress",
]);

export type UpdateIntakeLocationPayload =
  | {
      location: IntakeStructuredLocation & {
        source?: "dispatcher_selected" | "manual_entry";
      };
    }
  | { locationId: string };

export type ClassifyServiceCasePayload = {
  title?: string;
  description?: string;
  priorityLevel?: "low" | "medium" | "high" | "urgent";
};

/** Row shape returned by POST classify/service-case (service_cases table). */
export type ClassifyServiceCaseRow = {
  public_uuid: string;
  case_code: string;
  title: string;
  description?: string | null;
  priority_level?: string | null;
  status_code?: string | null;
};

export type PromoteEmergencyPayload = {
  severityCode: "low" | "medium" | "high" | "critical";
  incidentTitle?: string;
  incidentDescription?: string;
};

export type LinkIntakeToIncidentPayload = {
  intakeReportPublicUuid: string;
  linkType: "supporting_report" | "follow_up_report";
  note?: string;
};

export type OperationsIncidentRow = {
  public_uuid: string;
  incident_code?: string;
  title: string;
  description?: string | null;
  origin_type?: string | null;
  status_code: string;
  category_code?: string;
  severity_code?: string;
  location?: {
    address_text?: string | null;
    place_name?: string | null;
  } | null;
  location_text?: string | null;
  reported_at?: string | null;
  resolved_at?: string | null;
  closed_at?: string | null;
  created_at?: string;
  updated_at?: string;
};

export type OperationsIncidentsResponse = {
  incidents: OperationsIncidentRow[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
};

export type ClassifyServiceCaseResponse = {
  message?: string;
  service_case?: ClassifyServiceCaseRow;
  intake?: unknown;
};

export type PromoteEmergencyResponse = {
  message?: string;
  incident?: {
    public_uuid?: string;
    incident_code?: string;
    title?: string;
    status_code?: string;
    severity_code?: string;
    [key: string]: unknown;
  };
};

export type LinkIntakeToIncidentResponse = {
  message?: string;
  link?: unknown;
};

export type RouteMutationAction =
  | "service_case"
  | "emergency"
  | "link"
  | "location";

export type PendingIntakeListParams = {
  statusFilter: TriageStatusFilter;
  categoryFilter: TriageCategoryFilter;
  sortOrder: TriageSortOrder;
  limit?: number;
  offset?: number;
};

export type OperationsIntakeListQuery = {
  intake_status?: string;
  categoryCode?: string;
  sortOrder?: TriageSortOrder;
  limit?: number;
  offset?: number;
};

const OVERSIGHT_INTAKE_DEFAULT_LIMIT = 100;

export async function listOperationsIntakeReports(
  query: OperationsIntakeListQuery = {},
): Promise<OperationsIntakeReportsResponse> {
  const sortOrder = query.sortOrder ?? "newest";
  const search = new URLSearchParams({
    limit: String(query.limit ?? OVERSIGHT_INTAKE_DEFAULT_LIMIT),
    offset: String(query.offset ?? DEFAULT_OFFSET),
    sort: toSortParam(sortOrder),
  });

  if (query.intake_status?.trim()) {
    search.set("intake_status", query.intake_status.trim());
  }
  if (query.categoryCode?.trim()) {
    search.set("categoryCode", query.categoryCode.trim());
  }

  return apiGet<OperationsIntakeReportsResponse>(
    `/operations/intake-reports?${search.toString()}`,
  );
}

function dedupeByPublicUuid<T extends { public_uuid: string }>(items: T[]): T[] {
  const seen = new Set<string>();
  const result: T[] = [];
  for (const item of items) {
    if (seen.has(item.public_uuid)) continue;
    seen.add(item.public_uuid);
    result.push(item);
  }
  return result;
}

function toSortParam(sortOrder: TriageSortOrder): string {
  return sortOrder === "newest" ? "reported_at_desc" : "reported_at_asc";
}

function buildListQueryString(
  params: PendingIntakeListParams & { intake_status: string },
): string {
  const search = new URLSearchParams({
    limit: String(params.limit ?? DEFAULT_LIMIT),
    offset: String(params.offset ?? DEFAULT_OFFSET),
    sort: toSortParam(params.sortOrder),
    intake_status: params.intake_status,
  });

  if (params.categoryFilter !== "all") {
    search.set("categoryCode", params.categoryFilter);
  }

  return search.toString();
}

function sortPendingReports(
  reports: OperationsIntakeReport[],
  sortOrder: TriageSortOrder,
): OperationsIntakeReport[] {
  const getTimestamps = (report: OperationsIntakeReport) => [
    report.reported_at,
    report.created_at,
    report.updated_at,
  ];

  return sortOrder === "newest"
    ? sortNewestFirst(reports, getTimestamps)
    : sortOldestFirst(reports, getTimestamps);
}

async function fetchIntakeReportsByStatus(
  params: PendingIntakeListParams,
  intakeStatus: string,
): Promise<OperationsIntakeReport[]> {
  const query = buildListQueryString({ ...params, intake_status: intakeStatus });
  const data = await apiGet<OperationsIntakeReportsResponse>(
    `/operations/intake-reports?${query}`,
  );
  return data.intake_reports ?? [];
}

export async function fetchDispatcherOverview(): Promise<DispatcherOverviewResponse> {
  return apiGet<DispatcherOverviewResponse>("/operations/dispatcher/overview");
}

export async function fetchPendingIntakeReports(
  params: PendingIntakeListParams,
): Promise<OperationsIntakeReport[]> {
  if (params.statusFilter === "all") {
    return fetchAllPendingIntakeReports(params);
  }

  const reports = await fetchIntakeReportsByStatus(params, params.statusFilter);
  return sortPendingReports(reports, params.sortOrder);
}

export async function fetchAllPendingIntakeReports(
  params: PendingIntakeListParams,
): Promise<OperationsIntakeReport[]> {
  const [received, underReview] = await Promise.all([
    fetchIntakeReportsByStatus(params, "received"),
    fetchIntakeReportsByStatus(params, "under_review"),
  ]);

  const merged = dedupeByPublicUuid([...received, ...underReview]);
  return sortPendingReports(merged, params.sortOrder);
}

export async function fetchIntakeReportDetail(
  reportPublicUuid: string,
): Promise<OperationsIntakeReport> {
  const data = await apiGet<OperationsIntakeReportResponse>(
    `/operations/intake-reports/${encodeURIComponent(reportPublicUuid)}`,
  );

  if (!data.intake_report) {
    throw new ApiError({
      status: 404,
      code: "INTAKE_REPORT_NOT_FOUND",
      message: "Intake report not found.",
    });
  }

  return data.intake_report;
}

export function mapApiErrorToTriageMessage(
  error: unknown,
  context: "queue" | "detail" | "overview",
): string {
  if (error instanceof ApiError) {
    if (error.status === 403 || error.code === "FORBIDDEN") {
      return "You do not have permission to view the dispatcher triage queue.";
    }
    if (error.status === 0 || error.code === "NETWORK_ERROR") {
      return "Could not reach the server. Please try again.";
    }
    if (context === "detail" && error.status === 404) {
      return "This intake report could not be loaded.";
    }
  }

  if (context === "overview") {
    return "Unable to load pending report count.";
  }
  if (context === "detail") {
    return "Unable to load intake report details.";
  }
  return "Unable to load pending intake reports.";
}

export async function updateIntakeReportedLocation(
  reportPublicUuid: string,
  payload: UpdateIntakeLocationPayload,
): Promise<UpdateIntakeLocationResponse> {
  return apiPatch<UpdateIntakeLocationResponse>(
    `/intake/reports/${encodeURIComponent(reportPublicUuid)}/location`,
    payload,
  );
}

export async function getOperationsIntakeLocationHistory(
  reportPublicUuid: string,
): Promise<IntakeLocationHistoryResponse> {
  return apiGet<IntakeLocationHistoryResponse>(
    `/operations/intake-reports/${encodeURIComponent(reportPublicUuid)}/reported-location-history`,
  );
}

export async function classifyIntakeAsServiceCase(
  reportPublicUuid: string,
  payload: ClassifyServiceCasePayload,
): Promise<ClassifyServiceCaseResponse> {
  return apiPost<ClassifyServiceCaseResponse>(
    `/intake/reports/${encodeURIComponent(reportPublicUuid)}/classify/service-case`,
    payload,
  );
}

export async function promoteIntakeToEmergencyIncident(
  reportPublicUuid: string,
  payload: PromoteEmergencyPayload,
): Promise<PromoteEmergencyResponse> {
  return apiPost<PromoteEmergencyResponse>(
    `/operations/intake-reports/${encodeURIComponent(reportPublicUuid)}/promote/emergency`,
    payload,
  );
}

export type OperationsIncidentsQuery = {
  limit?: number;
  offset?: number;
  status_code?: string;
  reported_after?: string;
  reported_before?: string;
};

export async function getOperationsIncidents(
  query: OperationsIncidentsQuery = {},
): Promise<OperationsIncidentsResponse> {
  const search = new URLSearchParams({
    limit: String(query.limit ?? INCIDENTS_DEFAULT_LIMIT),
    offset: String(query.offset ?? DEFAULT_OFFSET),
  });

  if (query.status_code) {
    search.set("status_code", query.status_code);
  }
  if (query.reported_after) {
    search.set("reported_after", query.reported_after);
  }
  if (query.reported_before) {
    search.set("reported_before", query.reported_before);
  }

  return apiGet<OperationsIncidentsResponse>(`/operations/incidents?${search.toString()}`);
}

export async function linkIntakeToIncident(
  incidentPublicUuid: string,
  payload: LinkIntakeToIncidentPayload,
): Promise<LinkIntakeToIncidentResponse> {
  return apiPost<LinkIntakeToIncidentResponse>(
    `/operations/incidents/${encodeURIComponent(incidentPublicUuid)}/intake-reports`,
    payload,
  );
}

export function mapApiErrorToRouteMessage(
  error: unknown,
  action: RouteMutationAction,
): string {
  if (error instanceof ApiError) {
    if (error.status === 403 || error.code === "FORBIDDEN") {
      return "You do not have permission to perform this action.";
    }
    if (error.status === 0 || error.code === "NETWORK_ERROR") {
      return "Could not reach the server. Please try again.";
    }

    const codeHints: Record<string, string> = {
      INTAKE_NOT_CLASSIFIABLE:
        "This report may already have been routed. Refresh the queue and try again.",
      SERVICE_CASE_REQUIRES_REPORTER_USER:
        "This report cannot be opened as a service case without a registered reporter.",
      SERVICE_CASE_REQUIRES_LOCATION:
        "Add a reported location before creating a service case.",
      EMERGENCY_INCIDENT_REQUIRES_LOCATION:
        "Confirm the report location and try again.",
      INTAKE_NOT_PROMOTABLE:
        "This report cannot be promoted in its current status.",
      INTAKE_ALREADY_LINKED:
        "This report is already linked to an incident or case.",
      INCIDENT_NOT_FOUND: "The selected incident could not be found.",
      INCIDENT_NOT_LINKABLE:
        "The selected incident cannot accept new intake links.",
      INTAKE_REPORT_NOT_FOUND: "This intake report could not be found.",
    };

    const hint = error.code ? codeHints[error.code] : undefined;
    if (hint) return hint;

    if (error.status === 409) {
      if (action === "service_case") {
        return "Unable to create service case. This report may already have been routed.";
      }
      if (action === "emergency") {
        return "Unable to create emergency incident. This report may already have been routed.";
      }
      if (action === "link") {
        return "Unable to link this report to the selected incident.";
      }
    }

    if (error.status === 422) {
      if (action === "service_case") {
        return "Unable to create service case. Check the report details and try again.";
      }
      if (action === "emergency") {
        return "Unable to create emergency incident. Confirm the report location and try again.";
      }
      if (action === "link") {
        return "Unable to link this report to the selected incident.";
      }
      if (action === "location") {
        return "Could not update the reported location. Check the coordinates and try again.";
      }
    }

    if (error.message && error.message !== "Request failed.") {
      return error.message;
    }
  }

  if (action === "service_case") {
    return "Unable to create service case. Please try again.";
  }
  if (action === "emergency") {
    return "Unable to create emergency incident. Confirm the report location and try again.";
  }
  if (action === "link") {
    return "Unable to link this report to the selected incident.";
  }
  if (action === "location") {
    return "Could not update the reported location. Please try again.";
  }
  return "Something went wrong. Please try again.";
}
