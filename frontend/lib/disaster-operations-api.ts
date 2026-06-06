import { apiDelete, apiGet, apiPatch, apiPost } from "@/lib/api";
import type {
  ActivateReliefHubPayload,
  ActivateShelterPayload,
  ActivationDeactivationPayload,
  AddAffectedAreasPayload,
  AssignResponsibilityPayload,
  CreateDisasterPayload,
  CreateDisasterResponse,
  CreateReliefDistributionPayload,
  CreateReliefRequestPayload,
  DeclarationAmendmentPayload,
  DisasterAssessmentPayload,
  DisasterDashboardResponse,
  DisasterIncidentCandidatesResponse,
  DisasterLinkedIncidentsResponse,
  DisasterListResponse,
  DisasterStatusPayload,
  InitialDeclarationPayload,
  LinkIncidentPayload,
  PostDisasterStatusResponse,
  ReliefRequestActionPayload,
  RevokeResponsibilityPayload,
  ShelterManagingAgencyPayload,
  ShelterOccupancyPayload,
  StockReceiptPayload,
  UnlinkIncidentPayload,
} from "@/types/disaster-operations";

function disasterPath(disasterPublicUuid: string) {
  return `/operations/disasters/${encodeURIComponent(disasterPublicUuid)}`;
}

export async function listDisasters(): Promise<DisasterListResponse> {
  const data = await apiGet<DisasterListResponse>("/operations/disasters");
  const disasters = data.disasters;
  return {
    ...data,
    disasters: Array.isArray(disasters) ? disasters : [],
  };
}

export function getDisasterDashboard(disasterPublicUuid: string) {
  return apiGet<DisasterDashboardResponse>(disasterPath(disasterPublicUuid));
}

export function createDisaster(body: CreateDisasterPayload) {
  return apiPost<CreateDisasterResponse, CreateDisasterPayload>(
    "/operations/disasters",
    body,
  );
}

export function addDisasterAffectedAreas(
  disasterPublicUuid: string,
  body: AddAffectedAreasPayload,
) {
  return apiPost<DisasterDashboardResponse, AddAffectedAreasPayload>(
    `${disasterPath(disasterPublicUuid)}/affected-areas`,
    body,
  );
}

export function postInitialDisasterDeclaration(
  disasterPublicUuid: string,
  body: InitialDeclarationPayload,
) {
  return apiPost<DisasterDashboardResponse, InitialDeclarationPayload>(
    `${disasterPath(disasterPublicUuid)}/declarations/initial`,
    body,
  );
}

export function patchDisasterAffectedAreaAssessment(
  disasterPublicUuid: string,
  affectedAreaPublicUuid: string,
  body: DisasterAssessmentPayload,
) {
  return apiPatch<DisasterDashboardResponse, DisasterAssessmentPayload>(
    `${disasterPath(disasterPublicUuid)}/affected-areas/${encodeURIComponent(affectedAreaPublicUuid)}`,
    body,
  );
}

export function postDisasterStatus(
  disasterPublicUuid: string,
  body: DisasterStatusPayload,
) {
  return apiPost<PostDisasterStatusResponse, DisasterStatusPayload>(
    `${disasterPath(disasterPublicUuid)}/status`,
    body,
  );
}

export function postDisasterResponsibility(
  disasterPublicUuid: string,
  body: AssignResponsibilityPayload,
) {
  return apiPost<DisasterDashboardResponse, AssignResponsibilityPayload>(
    `${disasterPath(disasterPublicUuid)}/responsibilities`,
    body,
  );
}

export function postRevokeDisasterResponsibility(
  disasterPublicUuid: string,
  body: RevokeResponsibilityPayload,
) {
  return apiPost<DisasterDashboardResponse, RevokeResponsibilityPayload>(
    `${disasterPath(disasterPublicUuid)}/responsibilities/revoke`,
    body,
  );
}

export function postDisasterDeclarationAmendment(
  disasterPublicUuid: string,
  body: DeclarationAmendmentPayload,
) {
  return apiPost<DisasterDashboardResponse, DeclarationAmendmentPayload>(
    `${disasterPath(disasterPublicUuid)}/declarations/amendments`,
    body,
  );
}

export function getDisasterIncidentCandidates(disasterPublicUuid: string) {
  return apiGet<DisasterIncidentCandidatesResponse>(
    `${disasterPath(disasterPublicUuid)}/incidents/candidates`,
  );
}

export function getDisasterLinkedIncidents(disasterPublicUuid: string) {
  return apiGet<DisasterLinkedIncidentsResponse>(
    `${disasterPath(disasterPublicUuid)}/incidents`,
  );
}

export function postLinkDisasterIncident(
  disasterPublicUuid: string,
  body: LinkIncidentPayload,
) {
  return apiPost<{ link: unknown }, LinkIncidentPayload>(
    `${disasterPath(disasterPublicUuid)}/incidents`,
    body,
  );
}

export function deleteUnlinkDisasterIncident(
  disasterPublicUuid: string,
  incidentPublicUuid: string,
  body: UnlinkIncidentPayload,
) {
  return apiDelete<{ link: unknown }, UnlinkIncidentPayload>(
    `${disasterPath(disasterPublicUuid)}/incidents/${encodeURIComponent(incidentPublicUuid)}`,
    body,
  );
}

export function postActivateDisasterShelter(
  disasterPublicUuid: string,
  body: ActivateShelterPayload,
) {
  return apiPost<{ activation: unknown }, ActivateShelterPayload>(
    `${disasterPath(disasterPublicUuid)}/shelters`,
    body,
  );
}

export function postShelterManagingAgency(
  disasterPublicUuid: string,
  shelterActivationPublicUuid: string,
  body: ShelterManagingAgencyPayload,
) {
  return apiPost<{ activation: unknown }, ShelterManagingAgencyPayload>(
    `${disasterPath(disasterPublicUuid)}/shelters/${encodeURIComponent(shelterActivationPublicUuid)}/managing-agency`,
    body,
  );
}

export function postShelterOccupancy(
  disasterPublicUuid: string,
  shelterActivationPublicUuid: string,
  body: ShelterOccupancyPayload,
) {
  return apiPost<{ snapshot: unknown }, ShelterOccupancyPayload>(
    `${disasterPath(disasterPublicUuid)}/shelters/${encodeURIComponent(shelterActivationPublicUuid)}/occupancy`,
    body,
  );
}

export function postDeactivateDisasterShelter(
  disasterPublicUuid: string,
  shelterActivationPublicUuid: string,
  body: ActivationDeactivationPayload = {},
) {
  return apiPost<{ activation: unknown }, ActivationDeactivationPayload>(
    `${disasterPath(disasterPublicUuid)}/shelters/${encodeURIComponent(shelterActivationPublicUuid)}/deactivate`,
    body,
  );
}

export function postActivateDisasterReliefHub(
  disasterPublicUuid: string,
  body: ActivateReliefHubPayload,
) {
  return apiPost<{ activation: unknown }, ActivateReliefHubPayload>(
    `${disasterPath(disasterPublicUuid)}/relief-hubs`,
    body,
  );
}

export function postReliefHubStockReceipt(
  disasterPublicUuid: string,
  hubActivationPublicUuid: string,
  body: StockReceiptPayload,
) {
  return apiPost<{ receipt: unknown }, StockReceiptPayload>(
    `${disasterPath(disasterPublicUuid)}/relief-hubs/${encodeURIComponent(hubActivationPublicUuid)}/stock-receipts`,
    body,
  );
}

export function postDeactivateDisasterReliefHub(
  disasterPublicUuid: string,
  hubActivationPublicUuid: string,
  body: ActivationDeactivationPayload = {},
) {
  return apiPost<{ activation: unknown }, ActivationDeactivationPayload>(
    `${disasterPath(disasterPublicUuid)}/relief-hubs/${encodeURIComponent(hubActivationPublicUuid)}/deactivate`,
    body,
  );
}

export function postDisasterReliefRequest(
  disasterPublicUuid: string,
  body: CreateReliefRequestPayload,
) {
  return apiPost<{ request: unknown }, CreateReliefRequestPayload>(
    `${disasterPath(disasterPublicUuid)}/relief-requests`,
    body,
  );
}

export function postApproveReliefRequest(
  reliefRequestPublicUuid: string,
  body?: ReliefRequestActionPayload,
) {
  return apiPost<{ request: unknown }, ReliefRequestActionPayload>(
    `/operations/disasters/relief-requests/${encodeURIComponent(reliefRequestPublicUuid)}/approve`,
    body ?? {},
  );
}

export function postRejectReliefRequest(
  reliefRequestPublicUuid: string,
  body?: ReliefRequestActionPayload,
) {
  return apiPost<{ request: unknown }, ReliefRequestActionPayload>(
    `/operations/disasters/relief-requests/${encodeURIComponent(reliefRequestPublicUuid)}/reject`,
    body ?? {},
  );
}

export function postDisasterReliefDistribution(
  disasterPublicUuid: string,
  body: CreateReliefDistributionPayload,
) {
  return apiPost<{ distribution: unknown }, CreateReliefDistributionPayload>(
    `${disasterPath(disasterPublicUuid)}/relief-distributions`,
    body,
  );
}
