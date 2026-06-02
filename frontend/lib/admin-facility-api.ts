import { apiGet, apiPatch, apiPost, apiPut } from "@/lib/api";
import type {
  AdminActivateFacilityResponse,
  AdminDeactivateFacilityResponse,
  AdminFacilitiesListResponse,
  AdminFacilityDetailResponse,
  CreateFacilityPayload,
  CreateFacilityResponse,
  UpdateFacilityCapabilitiesPayload,
  UpdateFacilityDefaultCapacitiesPayload,
  UpdateFacilityResponse,
} from "@/types/admin-facility";

export async function listAdminFacilities(): Promise<AdminFacilitiesListResponse> {
  const data = await apiGet<AdminFacilitiesListResponse>("/admin/facilities");
  return {
    ...data,
    facilities: data.facilities ?? [],
  };
}

export function getAdminFacility(facilityPublicUuid: string) {
  return apiGet<AdminFacilityDetailResponse>(
    `/admin/facilities/${encodeURIComponent(facilityPublicUuid)}`,
  );
}

export function createAdminFacility(body: CreateFacilityPayload) {
  return apiPost<CreateFacilityResponse, CreateFacilityPayload>(
    "/admin/facilities",
    body,
  );
}

export function updateFacilityCapabilities(
  facilityPublicUuid: string,
  body: UpdateFacilityCapabilitiesPayload,
) {
  return apiPut<UpdateFacilityResponse, UpdateFacilityCapabilitiesPayload>(
    `/admin/facilities/${encodeURIComponent(facilityPublicUuid)}/capabilities`,
    body,
  );
}

export function updateFacilityDefaultCapacities(
  facilityPublicUuid: string,
  body: UpdateFacilityDefaultCapacitiesPayload,
) {
  return apiPut<UpdateFacilityResponse, UpdateFacilityDefaultCapacitiesPayload>(
    `/admin/facilities/${encodeURIComponent(facilityPublicUuid)}/default-capacities`,
    body,
  );
}

export function deactivateAdminFacility(facilityPublicUuid: string) {
  return apiPatch<AdminDeactivateFacilityResponse>(
    `/admin/facilities/${encodeURIComponent(facilityPublicUuid)}/deactivate`,
    {},
  );
}

export function activateAdminFacility(facilityPublicUuid: string) {
  return apiPatch<AdminActivateFacilityResponse>(
    `/admin/facilities/${encodeURIComponent(facilityPublicUuid)}/activate`,
    {},
  );
}
