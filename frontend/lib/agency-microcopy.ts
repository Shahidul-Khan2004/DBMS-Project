import { formatAgencyTypeLabel } from "@/lib/agency-dispatch-utils";

function normalizeAgencyType(typeCode: string | null | undefined): string {
  return (typeCode ?? "").toLowerCase().trim();
}

export function getAgencyWorkspaceTitle(agencyName: string | null | undefined): string {
  if (agencyName?.trim()) return `${agencyName.trim()} Workspace`;
  return "Agency Workspace";
}

export function getReadableAgencyTypeLabel(typeCode: string | null | undefined): string {
  const normalized = normalizeAgencyType(typeCode);
  if (normalized === "fire_service" || normalized === "fire") {
    return "Fire Service";
  }
  if (normalized === "police") {
    return "Police";
  }
  if (
    normalized === "medical_service" ||
    normalized === "medical" ||
    normalized === "ambulance"
  ) {
    return "Medical";
  }
  return formatAgencyTypeLabel(typeCode);
}

export function getAgencyOperationsSubtitle(
  typeCode: string | null | undefined,
  loading: boolean,
  failed: boolean,
): string {
  if (loading) return "Loading agency access...";
  if (failed) return "Response operations console";
  const readable = getReadableAgencyTypeLabel(typeCode);
  if (readable === "—") return "Response operations";
  return `${readable} response operations`;
}

export function getUnitAvailabilityMicrocopy(typeCode: string | null | undefined): string {
  const normalized = normalizeAgencyType(typeCode);
  if (normalized === "fire_service" || normalized === "fire") {
    return "Manage fire unit availability";
  }
  if (normalized === "police") {
    return "Manage police unit availability";
  }
  if (
    normalized === "medical_service" ||
    normalized === "medical" ||
    normalized === "ambulance"
  ) {
    return "Manage medical unit availability";
  }
  return "Manage unit availability";
}

export function getFieldUpdatesHelperText(typeCode: string | null | undefined): string {
  const normalized = normalizeAgencyType(typeCode);
  if (normalized === "fire_service" || normalized === "fire") {
    return "Field updates can include hazard, casualty, resource, or completion notes.";
  }
  return "Record formal field updates for assigned incidents.";
}
