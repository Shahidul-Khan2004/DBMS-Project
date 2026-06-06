import { formatBadgeLabel } from "@/components/ui/Badge";
import type {
  DisasterDetail,
  DisasterListItem,
  DisasterReliefHubActivation,
  DisasterReliefInventoryRow,
  DisasterReliefRequest,
  DisasterResponsibility,
  DisasterShelterActivation,
} from "@/types/disaster-operations";

export const DISASTER_EVENT_TYPE_OPTIONS = [
  { value: "flood", label: "Flood" },
  { value: "cyclone", label: "Cyclone" },
  { value: "earthquake", label: "Earthquake" },
  { value: "landslide", label: "Landslide" },
  { value: "epidemic", label: "Epidemic" },
  { value: "industrial_disaster", label: "Industrial Disaster" },
] as const;

export const DISASTER_SEVERITY_OPTIONS = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
  { value: "national", label: "National" },
] as const;

export const DISASTER_IMPACT_LEVEL_OPTIONS = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "severe", label: "Severe" },
] as const;

export const DISASTER_RESPONSIBILITY_TYPE_OPTIONS = [
  { value: "coordination", label: "Coordination" },
  { value: "shelter_management", label: "Shelter Management" },
  { value: "relief_management", label: "Relief Management" },
  { value: "medical_support", label: "Medical Support" },
  { value: "security_support", label: "Security Support" },
  { value: "rescue_support", label: "Rescue Support" },
] as const;

export const RELIEF_ITEM_OPTIONS = [
  { value: "rice", label: "Rice" },
  { value: "bottled_water", label: "Bottled Water" },
  { value: "blanket", label: "Blanket" },
  { value: "dry_food_packet", label: "Dry Food Packet" },
  { value: "medicine_kit", label: "Medicine Kit" },
  { value: "hygiene_kit", label: "Hygiene Kit" },
] as const;

const STATUS_LABELS: Record<string, string> = {
  monitoring: "Monitoring",
  declared: "Declared",
  resolved: "Resolved",
  closed: "Closed",
  cancelled: "Cancelled",
};

const RELIEF_REQUEST_STATUS_LABELS: Record<string, string> = {
  submitted: "Submitted",
  approved: "Approved",
  rejected: "Rejected",
  partially_fulfilled: "Partially Fulfilled",
  fulfilled: "Fulfilled",
};

const TERMINAL_DISASTER_STATUSES = new Set(["closed", "cancelled"]);

export type DisasterLifecycleAction = "resolve" | "close" | "cancel";

export function formatDisasterEventTypeLabel(
  code: string | null | undefined,
  name?: string | null,
) {
  if (name?.trim()) return name.trim();
  if (!code?.trim()) return "-";
  const match = DISASTER_EVENT_TYPE_OPTIONS.find((o) => o.value === code);
  return match?.label ?? formatBadgeLabel(code);
}

export function formatDisasterSeverityLabel(level: string | null | undefined) {
  if (!level?.trim()) return "-";
  const match = DISASTER_SEVERITY_OPTIONS.find((o) => o.value === level);
  return match?.label ?? formatBadgeLabel(level);
}

export function formatDisasterStatusLabel(statusCode: string | null | undefined) {
  if (!statusCode?.trim()) return "-";
  const key = statusCode.trim().toLowerCase();
  return STATUS_LABELS[key] ?? formatBadgeLabel(statusCode);
}

export function formatResponsibilityTypeLabel(type: string | null | undefined) {
  if (!type?.trim()) return "-";
  const match = DISASTER_RESPONSIBILITY_TYPE_OPTIONS.find((o) => o.value === type);
  return match?.label ?? formatBadgeLabel(type);
}

export function formatReliefItemLabel(code: string | null | undefined) {
  if (!code?.trim()) return "-";
  const match = RELIEF_ITEM_OPTIONS.find((o) => o.value === code);
  return match?.label ?? formatBadgeLabel(code);
}

export function getReliefInventoryItemLabel(
  row: Pick<DisasterReliefInventoryRow, "item_code" | "item_name">,
): string | null {
  const name = row.item_name?.trim();
  if (name) return name;
  const code = row.item_code?.trim();
  if (!code) return null;
  const label = formatReliefItemLabel(code);
  return label === "-" ? null : label;
}

export function formatReliefInventoryQuantity(
  quantity: DisasterReliefInventoryRow["quantity_on_hand"],
): string {
  if (quantity == null || quantity === "") return "0";
  const n = typeof quantity === "number" ? quantity : Number(quantity);
  if (!Number.isFinite(n)) return "—";
  return Number.isInteger(n)
    ? n.toLocaleString()
    : n.toLocaleString(undefined, { maximumFractionDigits: 2 });
}

export function getReliefHubInventoryRowsForActivation(
  inventory: DisasterReliefInventoryRow[],
  hub: Pick<DisasterReliefHubActivation, "relief_hub_public_uuid" | "facility_name">,
): DisasterReliefInventoryRow[] {
  return inventory.filter((row) => {
    const matchesHub =
      (hub.relief_hub_public_uuid &&
        row.relief_hub_public_uuid === hub.relief_hub_public_uuid) ||
      (hub.facility_name && row.facility_name === hub.facility_name);
    if (!matchesHub) return false;
    return getReliefInventoryItemLabel(row) != null;
  });
}

export function formatReliefHubInventorySummary(
  rows: DisasterReliefInventoryRow[],
): string | null {
  const parts = rows
    .map((row) => {
      const label = getReliefInventoryItemLabel(row);
      if (!label) return null;
      return `${label}: ${formatReliefInventoryQuantity(row.quantity_on_hand)}`;
    })
    .filter((part): part is string => part != null);
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function formatReliefRequestStatusLabel(status: string | null | undefined) {
  if (!status?.trim()) return "-";
  const key = status.trim().toLowerCase();
  return RELIEF_REQUEST_STATUS_LABELS[key] ?? formatBadgeLabel(status);
}

/** Matches backend relief distribution eligibility (rejected/fulfilled are terminal). */
export function isDistributableReliefRequest(status: string | null | undefined) {
  const code = status?.trim().toLowerCase();
  if (!code) return false;
  return code !== "rejected" && code !== "fulfilled";
}

export function formatReliefRequestSelectLabel(
  request: Pick<
    DisasterReliefRequest,
    "request_code" | "shelter_facility_name" | "status_code"
  >,
) {
  const code = request.request_code?.trim() || "Request";
  const shelter = request.shelter_facility_name?.trim() || "Shelter";
  const status = request.status_code?.trim().toLowerCase();
  if (status === "approved" || status === "partially_fulfilled") {
    return `${code} · ${shelter}`;
  }
  return `${code} · ${shelter} (${formatReliefRequestStatusLabel(request.status_code)})`;
}

export function getDisasterPublicUuid(
  item: Pick<DisasterListItem, "public_uuid"> | Pick<DisasterDetail, "public_uuid">,
) {
  return item.public_uuid;
}

export function getDisasterEventCode(
  item: Pick<DisasterListItem, "event_code"> | Pick<DisasterDetail, "event_code">,
) {
  return item.event_code;
}

export function formatAffectedAreaLabel(area: {
  upazila_name?: string;
  district_name?: string;
  division_name?: string;
}) {
  const parts = [
    area.upazila_name,
    area.district_name,
    area.division_name,
  ].filter(Boolean);
  return parts.join(", ") || "Unknown area";
}

export function getDeclarationStatusSummary(
  statusCode: string,
  declarationCount: number,
) {
  if (statusCode === "declared") {
    return declarationCount > 0
      ? `${declarationCount} declaration(s) on record`
      : "Declared";
  }
  if (declarationCount > 0) {
    return `${declarationCount} declaration(s)`;
  }
  return "No declaration yet";
}

export function isTerminalDisasterStatus(statusCode: string | null | undefined) {
  if (!statusCode?.trim()) return false;
  return TERMINAL_DISASTER_STATUSES.has(statusCode.trim().toLowerCase());
}

export function getAvailableLifecycleActions(
  statusCode: string | null | undefined,
): DisasterLifecycleAction[] {
  const code = statusCode?.trim().toLowerCase();
  if (code === "declared") return ["resolve", "cancel"];
  if (code === "resolved") return ["close"];
  return [];
}

export function isActiveDisasterActivation(activationStatus?: string) {
  return (activationStatus ?? "active") === "active";
}

export function getActiveDisasterShelters(shelters: DisasterShelterActivation[]) {
  return shelters
    .filter(
      (s) =>
        s.shelter_activation_public_uuid &&
        isActiveDisasterActivation(s.activation_status),
    )
    .sort((a, b) => (a.facility_name ?? "").localeCompare(b.facility_name ?? ""));
}

export function getLeadShelterManager(
  responsibilities: DisasterResponsibility[] | undefined,
): DisasterResponsibility | null {
  return (
    responsibilities?.find(
      (row) =>
        row.responsibility_type === "shelter_management" && row.is_lead === true,
    ) ?? null
  );
}

export function getActiveDisasterShelterFacilityUuids(
  shelters: DisasterShelterActivation[] | undefined,
): Set<string> {
  const uuids = new Set<string>();
  for (const shelter of getActiveDisasterShelters(shelters ?? [])) {
    if (shelter.facility_public_uuid) {
      uuids.add(shelter.facility_public_uuid);
    }
  }
  return uuids;
}

export function getActiveDisasterReliefHubs(hubs: DisasterReliefHubActivation[]) {
  return hubs
    .filter(
      (h) =>
        h.relief_hub_public_uuid &&
        isActiveDisasterActivation(h.activation_status),
    )
    .sort((a, b) => (a.facility_name ?? "").localeCompare(b.facility_name ?? ""));
}

export function getActiveDisasterReliefHubFacilityUuids(
  hubs: DisasterReliefHubActivation[] | undefined,
): Set<string> {
  const uuids = new Set<string>();
  for (const hub of getActiveDisasterReliefHubs(hubs ?? [])) {
    if (hub.facility_public_uuid) {
      uuids.add(hub.facility_public_uuid);
    }
  }
  return uuids;
}

export function isFinalizedDisasterActivation(activationStatus?: string) {
  return activationStatus === "finalized";
}

export function getShelterActivationPublicUuid(shelter: {
  shelter_activation_public_uuid?: string;
}) {
  return shelter.shelter_activation_public_uuid ?? "";
}

export function getReliefHubActivationPublicUuid(hub: {
  relief_hub_public_uuid?: string;
}) {
  return hub.relief_hub_public_uuid ?? "";
}

export function hasInitialDeclaration(
  declarations: Array<{ declaration_kind?: string }>,
) {
  return declarations.some((d) => d.declaration_kind === "initial");
}
