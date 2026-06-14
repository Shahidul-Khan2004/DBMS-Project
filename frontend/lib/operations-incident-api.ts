import { apiDelete, apiGet, apiPatch, apiPost } from "@/lib/api";
import type {
  AddIncidentOperationalNotePayload,
  AddIncidentOperationalNoteResponse,
  AssignIncidentAgencyPayload,
  AssignIncidentAgencyResponse,
  AvailableIncidentUnitsResponse,
  CreateIncidentDispatchPayload,
  CreateIncidentDispatchResponse,
  CreateStandaloneIncidentPayload,
  CreateStandaloneIncidentResponse,
  OperationsAgenciesWorkloadResponse,
  OperationsIncidentDetailResponse,
  OperationsResponseTimingResponse,
  PatchIncidentStatusPayload,
  PatchIncidentStatusResponse,
  UnlinkIncidentIntakeReportPayload,
  UnlinkIncidentIntakeReportResponse,
  UpdateDispatchStatusPayload,
  UpdateDispatchStatusResponse,
} from "@/types/operations-incident";

export async function getOperationsIncident(incidentPublicUuid: string) {
  const data = await apiGet<OperationsIncidentDetailResponse>(
    `/operations/incidents/${encodeURIComponent(incidentPublicUuid)}`,
  );

  return {
    ...data,
    linked_intake_reports: data.linked_intake_reports ?? [],
    timeline_preview: data.timeline_preview ?? [],
    participating_agencies: data.participating_agencies ?? [],
    dispatches: data.dispatches ?? [],
  };
}

export async function getOperationsAgenciesWorkload() {
  const data = await apiGet<OperationsAgenciesWorkloadResponse>(
    "/operations/agencies/workload",
  );

  return {
    ...data,
    agencies: data.agencies ?? [],
  };
}

export function assignAgencyToIncident(
  incidentPublicUuid: string,
  body: AssignIncidentAgencyPayload,
) {
  return apiPost<AssignIncidentAgencyResponse>(
    `/operations/incidents/${encodeURIComponent(incidentPublicUuid)}/agencies`,
    body,
  );
}

export type GetAvailableUnitsForIncidentOptions = {
  sort?: "distance_asc";
  includeDistance?: boolean;
};

export function getAvailableUnitsForIncident(
  incidentPublicUuid: string,
  options?: GetAvailableUnitsForIncidentOptions,
) {
  const query = new URLSearchParams({ incidentPublicUuid });
  if (options?.sort) query.set("sort", options.sort);
  if (options?.includeDistance) query.set("includeDistance", "true");
  return apiGet<AvailableIncidentUnitsResponse>(
    `/operations/units/available?${query.toString()}`,
  );
}

export function createIncidentDispatch(
  incidentPublicUuid: string,
  body: CreateIncidentDispatchPayload,
) {
  return apiPost<CreateIncidentDispatchResponse>(
    `/operations/incidents/${encodeURIComponent(incidentPublicUuid)}/dispatches`,
    body,
  );
}

export function updateOperationsDispatchStatus(
  dispatchPublicUuid: string,
  body: UpdateDispatchStatusPayload,
) {
  return apiPatch<UpdateDispatchStatusResponse>(
    `/operations/dispatches/${encodeURIComponent(dispatchPublicUuid)}/status`,
    body,
  );
}

export function patchIncidentStatus(
  incidentPublicUuid: string,
  body: PatchIncidentStatusPayload,
) {
  return apiPatch<PatchIncidentStatusResponse>(
    `/operations/incidents/${encodeURIComponent(incidentPublicUuid)}/status`,
    body,
  );
}

export function getIncidentResponseTiming(incidentPublicUuid: string) {
  return apiGet<OperationsResponseTimingResponse>(
    `/operations/incidents/${encodeURIComponent(incidentPublicUuid)}/response-timing`,
  );
}

export function addIncidentOperationalNote(
  incidentPublicUuid: string,
  body: AddIncidentOperationalNotePayload,
) {
  return apiPost<AddIncidentOperationalNoteResponse>(
    `/operations/incidents/${encodeURIComponent(incidentPublicUuid)}/notes`,
    body,
  );
}

export function unlinkIntakeReportFromIncident(
  incidentPublicUuid: string,
  reportPublicUuid: string,
  body: UnlinkIncidentIntakeReportPayload,
) {
  return apiDelete<UnlinkIncidentIntakeReportResponse>(
    `/operations/incidents/${encodeURIComponent(
      incidentPublicUuid,
    )}/intake-reports/${encodeURIComponent(reportPublicUuid)}`,
    body,
  );
}

export function createStandaloneIncident(body: CreateStandaloneIncidentPayload) {
  return apiPost<CreateStandaloneIncidentResponse>(
    "/operations/incidents",
    body,
  );
}
