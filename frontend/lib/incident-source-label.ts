import { formatBadgeLabel } from "@/components/ui/Badge";
import type { LinkedIntakeReport } from "@/types/incident-command";
import type { OperationsIntakeReport } from "@/types/operations-intake";

const INTAKE_CHANNEL_SOURCE_LABELS: Record<string, string> = {
  web_portal: "Citizen Intake",
  emergency_call: "999 Emergency Call",
  admin_entry: "Dispatcher Entry",
  agency_report: "Agency Report",
  mobile_app: "Mobile App Report",
};

const INCIDENT_ORIGIN_SOURCE_FALLBACK_LABELS: Record<string, string> = {
  admin_created: "Dispatcher Created",
  service_case_escalation: "Service Case Escalation",
  emergency_call: "999 Emergency Call",
  agency_report: "Agency Report",
  disaster_event: "Disaster Event",
};

export const LINKED_INTAKE_SOURCE_FALLBACK_LABEL = "Intake Report";

export const INCIDENT_SOURCE_NOT_AVAILABLE_LABEL = "Not Available";

export function formatIntakeChannelLabel(
  channelCode: string | null | undefined,
): string {
  if (!channelCode?.trim()) return "";
  const key = channelCode.trim().toLowerCase();
  return INTAKE_CHANNEL_SOURCE_LABELS[key] ?? formatBadgeLabel(key);
}

export function formatIncidentOriginSourceFallbackLabel(
  originType: string | null | undefined,
): string {
  if (!originType?.trim()) return INCIDENT_SOURCE_NOT_AVAILABLE_LABEL;
  const key = originType.trim().toLowerCase();
  return INCIDENT_ORIGIN_SOURCE_FALLBACK_LABELS[key] ?? formatBadgeLabel(key);
}

export function resolveIncidentSourceLabel({
  sourceLinkedReport,
  sourceIntakeDetail,
  incidentOriginType,
}: {
  sourceLinkedReport: LinkedIntakeReport | null;
  sourceIntakeDetail?: OperationsIntakeReport | null;
  incidentOriginType?: string | null;
}): string {
  if (sourceLinkedReport) {
    const channelCode = sourceIntakeDetail?.channel_code;
    if (channelCode?.trim()) {
      const channelLabel = formatIntakeChannelLabel(channelCode);
      if (channelLabel) return channelLabel;
    }
    return LINKED_INTAKE_SOURCE_FALLBACK_LABEL;
  }

  return formatIncidentOriginSourceFallbackLabel(incidentOriginType);
}
