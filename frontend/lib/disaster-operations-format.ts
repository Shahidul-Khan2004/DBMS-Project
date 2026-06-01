import { formatBadgeLabel } from "@/components/ui/Badge";
import type { DisasterDetail, DisasterListItem } from "@/types/disaster-operations";

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

const STATUS_LABELS: Record<string, string> = {
  monitoring: "Monitoring",
  declared: "Declared",
  resolved: "Resolved",
  closed: "Closed",
  cancelled: "Cancelled",
};

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
