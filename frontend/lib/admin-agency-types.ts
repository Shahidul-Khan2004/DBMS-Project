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

export type AgencyCategoryOption = {
  code: string;
  label: string;
  count: number;
};

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
      return "Infrastructure";
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

function sortAgencyTypeCodes(codes: string[]): string[] {
  const known = new Set(ADMIN_AGENCY_TYPE_SORT_ORDER);
  const knownCodes = ADMIN_AGENCY_TYPE_SORT_ORDER.filter((code) =>
    codes.includes(code),
  );
  const unknownCodes = codes
    .filter((code) => !known.has(code))
    .sort((a, b) => a.localeCompare(b));
  return [...knownCodes, ...unknownCodes];
}

export function buildAgencyCategoryOptions(
  agencies: AdminAgencyListItem[],
): AgencyCategoryOption[] {
  const counts = new Map<string, number>();
  for (const agency of agencies) {
    const code = agency.agency_type_code;
    counts.set(code, (counts.get(code) ?? 0) + 1);
  }

  const typeCodes = sortAgencyTypeCodes([...counts.keys()]);

  const typeOptions: AgencyCategoryOption[] = typeCodes
    .map((code) => ({
      code,
      label: formatAdminAgencyTypeLabel(code),
      count: counts.get(code) ?? 0,
    }))
    .filter((option) => option.count > 0);

  return [
    { code: "all", label: "All", count: agencies.length },
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
