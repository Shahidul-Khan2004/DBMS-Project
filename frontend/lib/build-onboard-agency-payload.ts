import type { AdminOnboardAgencyOnlyPayload } from "@/types/admin-agency";

/** Loose map selection shape for coordinate extraction. */
export type OnboardAgencySelectedLocation = {
  latitude?: number;
  longitude?: number;
  lat?: number;
  lng?: number;
  latlng?: { lat?: number; lng?: number };
  position?: { lat?: number; lng?: number };
} | null;

export type OnboardAgencyFormState = {
  agencyCode: string;
  agencyName: string;
  agencyTypeCode: string;
  description?: string;
  addressText?: string;
  placeName?: string;
  selectedLocation?: OnboardAgencySelectedLocation;
};

export function getSelectedLocationCoordinates(
  selectedLocation: OnboardAgencySelectedLocation | undefined,
): { latitude: number; longitude: number } | null {
  if (!selectedLocation) return null;

  const latitude =
    selectedLocation.latitude ??
    selectedLocation.lat ??
    selectedLocation.latlng?.lat ??
    selectedLocation.position?.lat;

  const longitude =
    selectedLocation.longitude ??
    selectedLocation.lng ??
    selectedLocation.latlng?.lng ??
    selectedLocation.position?.lng;

  const latNum = Number(latitude);
  const lngNum = Number(longitude);

  if (!Number.isFinite(latNum) || !Number.isFinite(lngNum)) {
    return null;
  }

  if (latNum < -90 || latNum > 90 || lngNum < -180 || lngNum > 180) {
    return null;
  }

  return {
    latitude: latNum,
    longitude: lngNum,
  };
}

export function buildOnboardAgencyPayload(
  formState: OnboardAgencyFormState,
): AdminOnboardAgencyOnlyPayload {
  const agency: AdminOnboardAgencyOnlyPayload["agency"] = {
    agency_code: formState.agencyCode.trim(),
    name: formState.agencyName.trim(),
    agency_type_code: formState.agencyTypeCode,
  };

  const description = formState.description?.trim();
  if (description) {
    agency.description = description;
  }

  const coordinates = getSelectedLocationCoordinates(formState.selectedLocation);

  if (coordinates) {
    const addressText = formState.addressText?.trim();
    const placeName = formState.placeName?.trim();

    agency.head_office_location = {
      latitude: coordinates.latitude,
      longitude: coordinates.longitude,
      source: "manual_entry",
      ...(addressText ? { address_text: addressText } : {}),
      ...(placeName ? { place_name: placeName } : {}),
    };
  }

  return { agency };
}
