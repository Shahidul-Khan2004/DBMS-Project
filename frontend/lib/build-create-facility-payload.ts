import type { CreateFacilityPayload } from "@/types/admin-facility";
import { getSelectedLocationCoordinates } from "@/lib/build-onboard-agency-payload";
import type { OnboardAgencySelectedLocation } from "@/lib/build-onboard-agency-payload";

export type CreateFacilityFormState = {
  facilityCode: string;
  name: string;
  facilityTypeCode: string;
  addressText?: string;
  placeName?: string;
  adminAreaId?: number | null;
  selectedLocation?: OnboardAgencySelectedLocation;
};

export function buildCreateFacilityPayload(
  formState: CreateFacilityFormState,
): CreateFacilityPayload | null {
  const coordinates = getSelectedLocationCoordinates(formState.selectedLocation);
  if (!coordinates) return null;

  const location: CreateFacilityPayload["location"] = {
    latitude: coordinates.latitude,
    longitude: coordinates.longitude,
    source: "manual_entry",
  };

  const addressText = formState.addressText?.trim();
  const placeName = formState.placeName?.trim();
  if (addressText) location.address_text = addressText;
  if (placeName) location.place_name = placeName;
  if (formState.adminAreaId != null) {
    location.admin_area_id = formState.adminAreaId;
  }

  return {
    facilityCode: formState.facilityCode.trim(),
    name: formState.name.trim(),
    facilityTypeCode: formState.facilityTypeCode,
    location,
  };
}
