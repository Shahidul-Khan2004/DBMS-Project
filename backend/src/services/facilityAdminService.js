import * as facilityRepo from "../repositories/facilityAdminRepo.js";

export const listFacilities = facilityRepo.listFacilities;
export const getFacilityByPublicUuid = facilityRepo.getFacilityByPublicUuid;
export const createFacility = facilityRepo.createFacility;
export const setFacilityCapabilities = facilityRepo.setFacilityCapabilities;
export const setFacilityDefaultCapacities = facilityRepo.setFacilityDefaultCapacities;
