import { formatFacilityLocationSummary, formatFacilityTypeLabel } from "@/lib/admin-facility-format";
import type { AdminFacilityListItem } from "@/types/admin-facility";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

const SHELTER_ELIGIBLE_TYPES = new Set(["shelter", "school_shelter_capable"]);
const RELIEF_HUB_ELIGIBLE_TYPES = new Set(["relief_center", "warehouse"]);

export function getAffectedAdminAreaIds(
  dashboard: DisasterDashboardResponse | null | undefined,
): Set<number> {
  const ids = new Set<number>();
  for (const area of dashboard?.affected_areas ?? []) {
    if (typeof area.admin_area_id === "number") {
      ids.add(area.admin_area_id);
    }
  }
  return ids;
}

export function getFacilityAdminAreaId(
  facility: AdminFacilityListItem | null | undefined,
): number | null {
  const raw = facility?.location?.adminAreaId;
  return typeof raw === "number" ? raw : null;
}

export function isFacilityInAffectedArea(
  facility: AdminFacilityListItem,
  affectedAdminAreaIds: Set<number>,
): boolean {
  const adminAreaId = getFacilityAdminAreaId(facility);
  if (adminAreaId == null) return false;
  return affectedAdminAreaIds.has(adminAreaId);
}

export function isShelterEligibleFacility(facility: AdminFacilityListItem): boolean {
  return SHELTER_ELIGIBLE_TYPES.has(facility.facilityTypeCode);
}

export function isReliefHubEligibleFacility(facility: AdminFacilityListItem): boolean {
  return RELIEF_HUB_ELIGIBLE_TYPES.has(facility.facilityTypeCode);
}

export function filterFacilitiesByAllowList(
  facilities: AdminFacilityListItem[],
  allowedFacilityPublicUuids?: ReadonlySet<string>,
): AdminFacilityListItem[] {
  if (!allowedFacilityPublicUuids || allowedFacilityPublicUuids.size === 0) {
    return facilities;
  }
  return facilities.filter((facility) =>
    allowedFacilityPublicUuids.has(facility.publicUuid),
  );
}

export function excludeFacilitiesByPublicUuid(
  facilities: AdminFacilityListItem[],
  excludePublicUuids: ReadonlySet<string>,
): AdminFacilityListItem[] {
  if (excludePublicUuids.size === 0) {
    return facilities;
  }
  return facilities.filter(
    (facility) => !excludePublicUuids.has(facility.publicUuid),
  );
}

export function filterFacilitiesForSearch(
  facilities: AdminFacilityListItem[],
  query: string,
  eligibilityFn: (facility: AdminFacilityListItem) => boolean,
): AdminFacilityListItem[] {
  const q = query.trim().toLowerCase();
  const eligible = facilities.filter((facility) => facility.isActive && eligibilityFn(facility));
  if (!q) return eligible;

  return eligible.filter((facility) => {
    const name = facility.name.toLowerCase();
    const code = facility.facilityCode.toLowerCase();
    const typeLabel = formatFacilityTypeLabel(facility.facilityTypeCode).toLowerCase();
    const adminArea = facility.location?.adminAreaLabel?.toLowerCase() ?? "";
    const address = facility.location?.addressText?.toLowerCase() ?? "";
    const place = facility.location?.placeName?.toLowerCase() ?? "";
    const locationSummary = formatFacilityLocationSummary(facility.location)?.toLowerCase() ?? "";

    return (
      name.includes(q) ||
      code.includes(q) ||
      typeLabel.includes(q) ||
      adminArea.includes(q) ||
      address.includes(q) ||
      place.includes(q) ||
      locationSummary.includes(q)
    );
  });
}
