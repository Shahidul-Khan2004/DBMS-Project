/** Seeded `emergency_unit_types.type_code` values — no live lookup API. */
export const AGENCY_UNIT_TYPE_OPTIONS = [
  { value: "ambulance", label: "Ambulance" },
  { value: "fire_truck", label: "Fire Truck" },
  { value: "police_vehicle", label: "Police Vehicle" },
  { value: "rescue_boat", label: "Rescue Boat" },
  { value: "medical_van", label: "Medical Van" },
  { value: "utility_repair_vehicle", label: "Utility Repair Vehicle" },
  { value: "relief_truck", label: "Relief Truck" },
  { value: "command_vehicle", label: "Command Vehicle" },
  { value: "helicopter", label: "Helicopter" },
] as const;

export function getAgencyUnitTypeLabel(typeCode: string | null | undefined): string {
  if (!typeCode) return "—";
  const match = AGENCY_UNIT_TYPE_OPTIONS.find((option) => option.value === typeCode);
  if (match) return match.label;
  return typeCode
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}
