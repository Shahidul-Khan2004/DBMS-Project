import type { AdminFacilityListItem } from "@/types/admin-facility";

const SHELTER_TYPES = new Set(["shelter", "school_shelter_capable"]);
const RELIEF_HUB_TYPES = new Set(["relief_center", "warehouse"]);
const HOSPITAL_SUPPORT_TYPES = new Set([
  "hospital",
  "clinic",
  "blood_bank",
  "community_center",
]);

export type FacilityReadinessStats = {
  total: number;
  shelterCapable: number;
  reliefHubs: number;
  hospitalsSupport: number;
  inactive: number;
};

export function computeFacilityReadinessStats(
  facilities: AdminFacilityListItem[],
): FacilityReadinessStats {
  let shelterCapable = 0;
  let reliefHubs = 0;
  let hospitalsSupport = 0;
  let inactive = 0;

  for (const facility of facilities) {
    if (!facility.isActive) {
      inactive += 1;
      continue;
    }
    if (SHELTER_TYPES.has(facility.facilityTypeCode)) shelterCapable += 1;
    if (RELIEF_HUB_TYPES.has(facility.facilityTypeCode)) reliefHubs += 1;
    if (HOSPITAL_SUPPORT_TYPES.has(facility.facilityTypeCode)) {
      hospitalsSupport += 1;
    }
  }

  return {
    total: facilities.length,
    shelterCapable,
    reliefHubs,
    hospitalsSupport,
    inactive,
  };
}

export function filterFacilitiesByRegistryTab(
  facilities: AdminFacilityListItem[],
  tab: FacilityRegistryTab,
): AdminFacilityListItem[] {
  if (tab === "all") return facilities;
  if (tab === "inactive") return facilities.filter((f) => !f.isActive);

  const active = facilities.filter((f) => f.isActive);
  switch (tab) {
    case "shelters":
      return active.filter((f) => SHELTER_TYPES.has(f.facilityTypeCode));
    case "relief-hubs":
      return active.filter((f) => RELIEF_HUB_TYPES.has(f.facilityTypeCode));
    case "hospitals":
      return active.filter((f) => HOSPITAL_SUPPORT_TYPES.has(f.facilityTypeCode));
    case "warehouses":
      return active.filter((f) => f.facilityTypeCode === "warehouse");
    default:
      return active;
  }
}

export type FacilityRegistryTab =
  | "all"
  | "shelters"
  | "relief-hubs"
  | "hospitals"
  | "warehouses"
  | "inactive";

export const FACILITY_REGISTRY_TABS: { id: FacilityRegistryTab; label: string }[] =
  [
    { id: "all", label: "All" },
    { id: "shelters", label: "Shelters" },
    { id: "relief-hubs", label: "Relief Hubs" },
    { id: "hospitals", label: "Hospitals" },
    { id: "warehouses", label: "Warehouses" },
    { id: "inactive", label: "Inactive" },
  ];
