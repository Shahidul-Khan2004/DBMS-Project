import { formatBadgeLabel } from "@/components/ui/Badge";
import type { FacilityLocation } from "@/types/admin-facility";

export const FACILITY_TYPE_OPTIONS = [
  { value: "hospital", label: "Hospital" },
  { value: "clinic", label: "Clinic" },
  { value: "shelter", label: "Shelter" },
  { value: "blood_bank", label: "Blood Bank" },
  { value: "relief_center", label: "Relief Center" },
  { value: "warehouse", label: "Warehouse" },
  { value: "school_shelter_capable", label: "School / Shelter Capable" },
  { value: "community_center", label: "Community Center" },
] as const;

/** Codes must exist in backend `capabilities` seed table. */
export const FACILITY_CAPABILITY_OPTIONS = [
  { value: "temporary_shelter", label: "Temporary Shelter" },
  { value: "relief_distribution_hub", label: "Relief Distribution Hub" },
  { value: "food_distribution", label: "Food Distribution" },
  { value: "emergency_care", label: "Emergency Care" },
  { value: "blood_storage", label: "Blood Storage" },
  { value: "ambulance_service", label: "Ambulance Service" },
  { value: "medical_triage", label: "Medical Triage" },
] as const;

export const FACILITY_CAPACITY_TYPE_OPTIONS = [
  { value: "shelter_people", label: "Shelter People" },
  { value: "hospital_beds", label: "Hospital Beds" },
  { value: "emergency_beds", label: "Emergency Beds" },
] as const;

export function formatFacilityTypeLabel(typeCode: string | null | undefined) {
  if (!typeCode?.trim()) return "-";
  const match = FACILITY_TYPE_OPTIONS.find((o) => o.value === typeCode);
  return match?.label ?? formatBadgeLabel(typeCode);
}

/** Hides auto-generated coordinate placeholder stored as address_text. */
export function formatFacilityAddressText(
  addressText: string | null | undefined,
): string | null {
  const trimmed = addressText?.trim();
  if (!trimmed) return null;
  if (/^Coordinates:\s*-?\d/i.test(trimmed)) return null;
  return trimmed;
}

/** Compact location line for list rows: administrative area, then readable address/place. */
export function formatFacilityLocationSummary(
  location: FacilityLocation | null | undefined,
): string | null {
  if (!location) return null;

  const adminArea = location.adminAreaLabel?.trim();
  if (adminArea) return adminArea;

  const address = formatFacilityAddressText(location.addressText);
  if (address) return address;

  const placeName = location.placeName?.trim();
  if (placeName) return placeName;

  return null;
}

export function formatCapabilityLabel(code: string) {
  const match = FACILITY_CAPABILITY_OPTIONS.find((o) => o.value === code);
  return match?.label ?? formatBadgeLabel(code);
}

export function formatCapacityTypeLabel(type: string) {
  const match = FACILITY_CAPACITY_TYPE_OPTIONS.find((o) => o.value === type);
  return match?.label ?? formatBadgeLabel(type);
}
