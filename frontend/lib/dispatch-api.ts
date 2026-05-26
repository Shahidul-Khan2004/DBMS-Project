import { apiGet, apiPatch, apiPost } from "@/lib/api";
import type {
  AgencyParticipationResponse,
  AgencyWorkloadResponse,
  AvailableUnitsResponse,
  DispatchPriorityLevel,
  DispatchResponse,
  ResponseTimingResponse,
} from "@/types/dispatch";

export function addIncidentAgency(
  incidentPublicUuid: string,
  body: { agencyPublicUuid: string; isLeadAgency: boolean },
) {
  return apiPost<AgencyParticipationResponse>(
    `/operations/incidents/${incidentPublicUuid}/agencies`,
    body,
  );
}

export function getAvailableUnits(incidentPublicUuid: string) {
  const query = new URLSearchParams({ incidentPublicUuid });
  return apiGet<AvailableUnitsResponse>(
    `/operations/units/available?${query.toString()}`,
  );
}

export function createIncidentDispatch(
  incidentPublicUuid: string,
  body: {
    unitPublicUuid: string;
    priorityLevel: DispatchPriorityLevel;
    note?: string;
  },
) {
  return apiPost<DispatchResponse>(
    `/operations/incidents/${incidentPublicUuid}/dispatches`,
    body,
  );
}

export function updateDispatchStatus(
  dispatchPublicUuid: string,
  body: { statusCode: string; note?: string },
) {
  return apiPatch<DispatchResponse>(
    `/operations/dispatches/${dispatchPublicUuid}/status`,
    body,
  );
}

export function getAgencyWorkload() {
  return apiGet<AgencyWorkloadResponse>("/operations/agencies/workload");
}

export function getIncidentResponseTiming(incidentPublicUuid: string) {
  return apiGet<ResponseTimingResponse>(
    `/operations/incidents/${incidentPublicUuid}/response-timing`,
  );
}
