import * as facilityRepo from "../repositories/facilityAdminRepo.js";
import { resolveGeoSortFromQuery } from "./geoSortService.js";

export async function listFacilities(query = {}, options = {}) {
  const { geoSort } = await resolveGeoSortFromQuery(query);
  return facilityRepo.listFacilities({ ...options, geoSort });
}
export const getFacilityByPublicUuid = facilityRepo.getFacilityByPublicUuid;
export const createFacility = facilityRepo.createFacility;
export const setFacilityCapabilities = facilityRepo.setFacilityCapabilities;
export const setFacilityDefaultCapacities = facilityRepo.setFacilityDefaultCapacities;
