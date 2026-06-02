import type { AdminAgencyListItem } from "@/types/admin-agency";

/** Seeded `agency_types.type_code` values — not a live lookup API. */
export const ADMIN_AGENCY_TYPE_OPTIONS = [
  { value: "police", label: "Police" },
  { value: "fire_service", label: "Fire Service" },
  { value: "medical_service", label: "Medical Service" },
  { value: "disaster_management", label: "Disaster Management" },
  { value: "infrastructure_emergency", label: "Infrastructure" },
  { value: "army", label: "Army" },
  { value: "ngo", label: "NGO" },
  { value: "utility_provider", label: "Utility Provider" },
  { value: "local_government", label: "Local Government" },
] as const;

export const ADMIN_AGENCY_TYPE_SORT_ORDER: readonly string[] = [
  "medical_service",
  "fire_service",
  "police",
  "disaster_management",
  "infrastructure_emergency",
  "army",
  "ngo",
  "utility_provider",
  "local_government",
];

/** Normal agency network types shown on the admin Agencies page. */
export const ADMIN_AGENCY_NETWORK_TYPE_CODES = [
  "medical_service",
  "fire_service",
  "police",
  "infrastructure_emergency",
  "utility_provider",
  "local_government",
] as const;

/** Agency types available in the onboard-agency modal (network types only). */
export const ADMIN_AGENCY_ONBOARD_TYPE_OPTIONS =
  ADMIN_AGENCY_NETWORK_TYPE_CODES.map((value) => ({
    value,
    label: formatAdminAgencyTypeLabel(value),
  }));

/** Excluded from the normal Agencies page — future Disaster Protocol workflow. */
export const ADMIN_AGENCY_DISASTER_PROTOCOL_TYPE_CODES = [
  "disaster_management",
  "army",
  "ngo",
] as const;

const disasterProtocolTypeSet = new Set<string>(
  ADMIN_AGENCY_DISASTER_PROTOCOL_TYPE_CODES,
);

const networkTypeSet = new Set<string>(ADMIN_AGENCY_NETWORK_TYPE_CODES);

export type AgencyCategoryOption = {
  code: string;
  label: string;
  count: number;
};

export function isAdminAgencyNetworkType(typeCode: string): boolean {
  return networkTypeSet.has(typeCode);
}

export function isAdminAgencyNetworkCategoryCode(code: string): boolean {
  return code === "all" || isAdminAgencyNetworkType(code);
}

export function filterAdminAgencyNetworkAgencies(
  agencies: AdminAgencyListItem[],
): AdminAgencyListItem[] {
  return agencies.filter(
    (agency) =>
      isAdminAgencyNetworkType(agency.agency_type_code) &&
      !disasterProtocolTypeSet.has(agency.agency_type_code),
  );
}

export function formatAdminAgencyTypeLabel(typeCode: string): string {
  switch (typeCode) {
    case "medical_service":
      return "Medical Service";
    case "fire_service":
      return "Fire Service";
    case "police":
      return "Police";
    case "disaster_management":
      return "Disaster Management";
    case "infrastructure_emergency":
      return "Infrastructure Emergency";
    case "army":
      return "Army";
    case "ngo":
      return "NGO";
    case "utility_provider":
      return "Utility Provider";
    case "local_government":
      return "Local Government";
    default:
      return typeCode
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
  }
}

export function buildAgencyCategoryOptions(
  agencies: AdminAgencyListItem[],
): AgencyCategoryOption[] {
  const networkAgencies = filterAdminAgencyNetworkAgencies(agencies);
  const counts = new Map<string, number>();

  for (const agency of networkAgencies) {
    const code = agency.agency_type_code;
    counts.set(code, (counts.get(code) ?? 0) + 1);
  }

  const typeOptions: AgencyCategoryOption[] =
    ADMIN_AGENCY_NETWORK_TYPE_CODES.map((code) => ({
      code,
      label: formatAdminAgencyTypeLabel(code),
      count: counts.get(code) ?? 0,
    }));

  return [
    { code: "all", label: "All", count: networkAgencies.length },
    ...typeOptions,
  ];
}

export function getAgencyListHeading(
  selectedType: string,
  visibleCount: number,
): { title: string; subtitle: string } {
  if (selectedType === "all") {
    return {
      title: "All Agencies",
      subtitle: `Showing ${visibleCount} ${visibleCount === 1 ? "agency" : "agencies"}`,
    };
  }

  const label = formatAdminAgencyTypeLabel(selectedType);
  return {
    title: `${label} Agencies`,
    subtitle: `Showing ${visibleCount} ${label.toLowerCase()} ${visibleCount === 1 ? "agency" : "agencies"}`,
  };
}
