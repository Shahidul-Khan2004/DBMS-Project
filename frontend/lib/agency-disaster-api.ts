import { apiGet, apiPost } from "@/lib/api";
import type {
  AgencyCreateReliefRequestPayload,
  AgencyCreateReliefRequestResponse,
  AgencyDisasterDetailResponse,
  AgencyDisasterIncidentsResponse,
  AgencyDisasterListResponse,
  AgencyDisasterReliefHubsResponse,
  AgencyDisasterReliefRequestsResponse,
  AgencyDisasterSheltersResponse,
  AgencyReliefHubStockReceiptPayload,
  AgencyReliefHubStockReceiptResponse,
  AgencyShelterOccupancyPayload,
  AgencyShelterOccupancyResponse,
} from "@/types/agency-disaster";

type ListQuery = {
  limit?: number;
  offset?: number;
};

function buildListQuery(query: ListQuery = {}): string {
  const search = new URLSearchParams();
  if (query.limit != null) search.set("limit", String(query.limit));
  if (query.offset != null) search.set("offset", String(query.offset));
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

function disasterPath(disasterPublicUuid: string) {
  return `/agency/disasters/${encodeURIComponent(disasterPublicUuid)}`;
}

export function listAgencyDisasters(
  query: ListQuery = {},
): Promise<AgencyDisasterListResponse> {
  return apiGet<AgencyDisasterListResponse>(`/agency/disasters${buildListQuery(query)}`);
}

export function getAgencyDisasterDetail(
  disasterPublicUuid: string,
): Promise<AgencyDisasterDetailResponse> {
  return apiGet<AgencyDisasterDetailResponse>(disasterPath(disasterPublicUuid));
}

export function getAgencyDisasterShelters(
  disasterPublicUuid: string,
): Promise<AgencyDisasterSheltersResponse> {
  return apiGet<AgencyDisasterSheltersResponse>(
    `${disasterPath(disasterPublicUuid)}/shelters`,
  );
}

export function getAgencyDisasterReliefHubs(
  disasterPublicUuid: string,
): Promise<AgencyDisasterReliefHubsResponse> {
  return apiGet<AgencyDisasterReliefHubsResponse>(
    `${disasterPath(disasterPublicUuid)}/relief-hubs`,
  );
}

export function postAgencyReliefHubStockReceipt(
  disasterPublicUuid: string,
  hubActivationPublicUuid: string,
  body: AgencyReliefHubStockReceiptPayload,
): Promise<AgencyReliefHubStockReceiptResponse> {
  return apiPost<AgencyReliefHubStockReceiptResponse, AgencyReliefHubStockReceiptPayload>(
    `${disasterPath(disasterPublicUuid)}/relief-hubs/${encodeURIComponent(hubActivationPublicUuid)}/stock-receipts`,
    body,
  );
}

export function postAgencyShelterOccupancy(
  disasterPublicUuid: string,
  shelterActivationPublicUuid: string,
  body: AgencyShelterOccupancyPayload,
): Promise<AgencyShelterOccupancyResponse> {
  return apiPost<AgencyShelterOccupancyResponse, AgencyShelterOccupancyPayload>(
    `${disasterPath(disasterPublicUuid)}/shelters/${encodeURIComponent(shelterActivationPublicUuid)}/occupancy`,
    body,
  );
}

export function getAgencyDisasterReliefRequests(
  disasterPublicUuid: string,
): Promise<AgencyDisasterReliefRequestsResponse> {
  return apiGet<AgencyDisasterReliefRequestsResponse>(
    `${disasterPath(disasterPublicUuid)}/relief-requests`,
  );
}

export function postAgencyDisasterReliefRequest(
  disasterPublicUuid: string,
  body: AgencyCreateReliefRequestPayload,
): Promise<AgencyCreateReliefRequestResponse> {
  return apiPost<AgencyCreateReliefRequestResponse, AgencyCreateReliefRequestPayload>(
    `${disasterPath(disasterPublicUuid)}/relief-requests`,
    body,
  );
}

export function getAgencyDisasterIncidents(
  disasterPublicUuid: string,
): Promise<AgencyDisasterIncidentsResponse> {
  return apiGet<AgencyDisasterIncidentsResponse>(
    `${disasterPath(disasterPublicUuid)}/incidents`,
  );
}
