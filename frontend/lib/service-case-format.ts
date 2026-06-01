import type {
  OperationsServiceCase,
  ServiceCaseAssignment,
  ServiceCaseLocation,
} from "@/types/service-case";

const SERVICE_CASE_CATEGORY_LABELS: Record<string, string> = {
  medical: "Medical",
  crime_public_safety: "Crime / Public Safety",
  fire: "Fire",
  natural_disaster: "Natural Disaster",
  infrastructure_emergency: "Infrastructure",
  relief_request: "Relief Request",
  blood_request: "Blood Request",
};

function titleCaseFromSnake(value: string) {
  return value
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

export function formatServiceCaseCategory(
  categoryCode: string | null | undefined,
): string {
  if (!categoryCode?.trim()) return "-";
  const key = categoryCode.trim().toLowerCase();
  return SERVICE_CASE_CATEGORY_LABELS[key] ?? titleCaseFromSnake(key);
}

export function formatServiceCaseCodeDisplay(caseCode: string | null | undefined) {
  if (!caseCode?.trim()) return "-";
  return caseCode.trim();
}

export type ServiceCaseAssignmentDisplay =
  | { kind: "unassigned"; label: "Unassigned" }
  | { kind: "assigned"; label: string }
  | { kind: "hidden" };

export function getServiceCaseAssignmentDisplay(
  serviceCase: Pick<OperationsServiceCase, "assigned_to_user_public_uuid">,
): ServiceCaseAssignmentDisplay {
  if (!serviceCase.assigned_to_user_public_uuid) {
    return { kind: "unassigned", label: "Unassigned" };
  }

  return { kind: "hidden" };
}

export function formatServiceCaseLocation(
  location: ServiceCaseLocation | null | undefined,
): string | null {
  if (!location) return null;
  const text =
    location.place_name?.trim() ||
    location.address_text?.trim() ||
    "Map location selected";
  return text || null;
}

export function getActiveServiceCaseAssignment(
  assignments: ServiceCaseAssignment[],
): ServiceCaseAssignment | null {
  const active = assignments.find(
    (row) =>
      row.assignment_status === "active" &&
      (row.ended_at == null || row.ended_at === ""),
  );
  return active ?? assignments[0] ?? null;
}

export function getServiceCaseAssignmentSummaryLabel(
  assignments: ServiceCaseAssignment[],
): string | null {
  const active = getActiveServiceCaseAssignment(assignments);
  if (!active) return null;
  const name = active.assigned_to?.full_name?.trim();
  if (name) return name;
  return "Assigned";
}

export function formatServiceCaseResolutionType(
  resolutionType: string | null | undefined,
): string {
  if (!resolutionType?.trim()) return "-";
  return titleCaseFromSnake(resolutionType.trim());
}

export function formatSourceChannel(
  sourceChannel: string | null | undefined,
): string | null {
  if (!sourceChannel?.trim()) return null;
  return titleCaseFromSnake(sourceChannel.trim());
}
