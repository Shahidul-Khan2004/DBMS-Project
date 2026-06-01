import { apiGet, apiPost } from "@/lib/api";
import type {
  AddAffectedAreasPayload,
  CreateDisasterPayload,
  CreateDisasterResponse,
  DisasterDashboardResponse,
  DisasterListResponse,
  InitialDeclarationPayload,
} from "@/types/disaster-operations";

export async function listDisasters(): Promise<DisasterListResponse> {
  const data = await apiGet<DisasterListResponse>("/operations/disasters");
  return {
    ...data,
    disasters: data.disasters ?? [],
  };
}

export function getDisasterDashboard(disasterPublicUuid: string) {
  return apiGet<DisasterDashboardResponse>(
    `/operations/disasters/${encodeURIComponent(disasterPublicUuid)}`,
  );
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
    `/operations/disasters/${encodeURIComponent(disasterPublicUuid)}/affected-areas`,
    body,
  );
}

export function postInitialDisasterDeclaration(
  disasterPublicUuid: string,
  body: InitialDeclarationPayload,
) {
  return apiPost<DisasterDashboardResponse, InitialDeclarationPayload>(
    `/operations/disasters/${encodeURIComponent(disasterPublicUuid)}/declarations/initial`,
    body,
  );
}
