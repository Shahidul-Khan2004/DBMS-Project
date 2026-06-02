import type { AdminFacilityListItem } from "@/types/admin-facility";

export const SUPPORT_FACILITY_TYPES = new Set([
  "hospital",
  "clinic",
  "blood_bank",
  "community_center",
]);

export function sortFacilitiesByName(items: AdminFacilityListItem[]) {
  return [...items].sort((a, b) => a.name.localeCompare(b.name));
}
