import { apiGet, apiPatch, apiPost } from "@/lib/api";
import type {
  AgencyCreateResponseLogBody,
  AgencyCreateResponseLogResponse,
  AgencyCreateUnitBody,
  AgencyCreateUnitResponse,
  AgencyDeactivateUnitResponse,
  AgencyDispatchesListResponse,
  AgencyIncidentsListResponse,
  AgencyListQuery,
  AgencyMeResponse,
  AgencyNotesListResponse,
  AgencyPatchDispatchStatusBody,
  AgencyPatchDispatchStatusResponse,
  AgencyPatchUnitBody,
  AgencyPatchUnitResponse,
  AgencyPatchUnitStatusBody,
  AgencyResponseLogsListResponse,
  AgencyUnitsListResponse,
} from "@/types/agency";

function buildListQuery(query: AgencyListQuery = {}): string {
  const search = new URLSearchParams();
  if (query.limit != null) {
    search.set("limit", String(query.limit));
  }
  if (query.offset != null) {
    search.set("offset", String(query.offset));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

export function getAgencyMe(): Promise<AgencyMeResponse> {
  return apiGet<AgencyMeResponse>("/agency/me");
}

export function getAgencyIncidents(
  query: AgencyListQuery = {},
): Promise<AgencyIncidentsListResponse> {
  return apiGet<AgencyIncidentsListResponse>(
    `/agency/incidents${buildListQuery(query)}`,
  );
}

export function getAgencyDispatches(
  query: AgencyListQuery = {},
): Promise<AgencyDispatchesListResponse> {
  return apiGet<AgencyDispatchesListResponse>(
    `/agency/dispatches${buildListQuery(query)}`,
  );
}

export function updateAgencyDispatchStatus(
  dispatchPublicUuid: string,
  body: AgencyPatchDispatchStatusBody,
): Promise<AgencyPatchDispatchStatusResponse> {
  return apiPatch<AgencyPatchDispatchStatusResponse>(
    `/agency/dispatches/${encodeURIComponent(dispatchPublicUuid)}/status`,
    body,
  );
}

export function getAgencyUnits(
  query: AgencyListQuery = {},
): Promise<AgencyUnitsListResponse> {
  return apiGet<AgencyUnitsListResponse>(`/agency/units${buildListQuery(query)}`);
}

export function createAgencyUnit(
  body: AgencyCreateUnitBody,
): Promise<AgencyCreateUnitResponse> {
  return apiPost<AgencyCreateUnitResponse>("/agency/units", body);
}

export function updateAgencyUnit(
  unitPublicUuid: string,
  body: AgencyPatchUnitBody,
): Promise<AgencyPatchUnitResponse> {
  return apiPatch<AgencyPatchUnitResponse>(
    `/agency/units/${encodeURIComponent(unitPublicUuid)}`,
    body,
  );
}

export function deactivateAgencyUnit(
  unitPublicUuid: string,
): Promise<AgencyDeactivateUnitResponse> {
  return apiPatch<AgencyDeactivateUnitResponse>(
    `/agency/units/${encodeURIComponent(unitPublicUuid)}/deactivate`,
    {},
  );
}

export function updateAgencyUnitStatus(
  unitPublicUuid: string,
  body: AgencyPatchUnitStatusBody,
): Promise<AgencyPatchUnitResponse> {
  return apiPatch<AgencyPatchUnitResponse>(
    `/agency/units/${encodeURIComponent(unitPublicUuid)}/status`,
    body,
  );
}

export function getAgencyIncidentNotes(
  incidentPublicUuid: string,
  query: AgencyListQuery = {},
): Promise<AgencyNotesListResponse> {
  return apiGet<AgencyNotesListResponse>(
    `/agency/incidents/${encodeURIComponent(incidentPublicUuid)}/notes${buildListQuery(query)}`,
  );
}

export function getAgencyIncidentResponseLogs(
  incidentPublicUuid: string,
  query: AgencyListQuery = {},
): Promise<AgencyResponseLogsListResponse> {
  return apiGet<AgencyResponseLogsListResponse>(
    `/agency/incidents/${encodeURIComponent(incidentPublicUuid)}/response-logs${buildListQuery(query)}`,
  );
}

export function createAgencyIncidentResponseLog(
  incidentPublicUuid: string,
  body: AgencyCreateResponseLogBody,
): Promise<AgencyCreateResponseLogResponse> {
  return apiPost<AgencyCreateResponseLogResponse>(
    `/agency/incidents/${encodeURIComponent(incidentPublicUuid)}/response-logs`,
    body,
  );
}
