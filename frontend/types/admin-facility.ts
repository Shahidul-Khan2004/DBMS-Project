export type FacilityLocation = {
  publicUuid?: string;
  adminAreaId?: number | null;
  adminAreaLabel?: string | null;
  latitude: number;
  longitude: number;
  addressText?: string | null;
  placeName?: string | null;
};

export type FacilityCapability = {
  capabilityCode: string;
  name?: string;
};

export type FacilityDefaultCapacity = {
  capacityType: string;
  totalCapacity: number;
};

export type AdminFacility = {
  id: number;
  publicUuid: string;
  facilityCode: string;
  name: string;
  facilityTypeCode: string;
  isActive: boolean;
  location?: FacilityLocation | null;
  capabilities?: FacilityCapability[];
  defaultCapacities?: FacilityDefaultCapacity[];
};

export type AdminFacilityListItem = {
  id: number;
  publicUuid: string;
  facilityCode: string;
  name: string;
  facilityTypeCode: string;
  isActive: boolean;
  location?: FacilityLocation | null;
};

export type AdminFacilitiesListResponse = {
  facilities: AdminFacilityListItem[];
};

export type AdminFacilityDetailResponse = {
  facility: AdminFacility;
};

export type CreateFacilityLocationPayload = {
  latitude: number;
  longitude: number;
  source: "manual_entry";
  address_text?: string;
  place_name?: string;
  admin_area_id?: number;
};

export type CreateFacilityPayload = {
  facilityCode: string;
  name: string;
  facilityTypeCode: string;
  location: CreateFacilityLocationPayload;
};

export type CreateFacilityResponse = {
  facility: AdminFacility;
};

export type UpdateFacilityCapabilitiesPayload = {
  capabilityCodes: string[];
};

export type UpdateFacilityDefaultCapacitiesPayload = {
  capacities: Array<{
    capacityType: string;
    totalCapacity: number;
  }>;
};

export type UpdateFacilityResponse = {
  facility: AdminFacility;
};

export type AdminDeactivateFacilityResponse = {
  message: string;
  facility: AdminFacility;
};

export type AdminActivateFacilityResponse = {
  message: string;
  facility: AdminFacility;
};
