import { formatBadgeLabel } from "@/components/ui/Badge";
import { hasValidReportedLocation } from "@/components/dispatcher/triage/reportedLocationCoords";
import { formatIncidentStatus } from "@/lib/incident-status";
import type { IncidentLocation } from "@/types/incident-command";
import type { OperationsIntakeReport } from "@/types/operations-intake";
import type {
  OperationsIncidentDetail,
  OperationsIncidentLocation,
  OperationsLinkedIntakeReport,
} from "@/types/operations-incident";

const INCIDENT_LINK_TYPE_LABELS: Record<string, string> = {
  primary_report: "Primary Report",
  supporting_report: "Supporting Report",
  follow_up_report: "Follow-up Report",
};

export function formatIncidentLinkType(linkType: string | null | undefined) {
  if (!linkType?.trim()) return "-";
  const key = linkType.trim().toLowerCase();
  return INCIDENT_LINK_TYPE_LABELS[key] ?? formatBadgeLabel(linkType);
}

export function formatIncidentField(value: string | null | undefined) {
  if (!value?.trim()) return "-";
  return formatBadgeLabel(value);
}

export { formatIncidentStatus };

export function getPrimaryLinkedIntakeReport(
  linkedReports: OperationsLinkedIntakeReport[],
): OperationsLinkedIntakeReport | undefined {
  return linkedReports.find((report) => report.link_type === "primary_report");
}

export function formatIncidentLocationText(
  location: OperationsIncidentLocation | null | undefined,
): string | null {
  if (!location) return null;
  const address = location.address_text?.trim();
  const place = location.place_name?.trim();
  if (address && place && address !== place) {
    return `${place} — ${address}`;
  }
  return address || place || null;
}

export function mapIntakeLocationToIncidentLocation(
  location: OperationsIntakeReport["location"],
): IncidentLocation | null {
  if (!location) return null;
  return {
    latitude: location.latitude,
    longitude: location.longitude,
    addressText: location.address_text,
    placeName: location.place_name,
  };
}

export function formatSourceIntakeLocationText(
  report: OperationsIntakeReport,
): string | null {
  return formatIncidentLocationText(report.location ?? null);
}

export function getIncidentReportedLocation(
  incident: OperationsIncidentDetail,
  linkedReports: OperationsLinkedIntakeReport[],
): OperationsIncidentLocation | null {
  if (
    incident.location &&
    hasValidReportedLocation({
      latitude: incident.location.latitude,
      longitude: incident.location.longitude,
    })
  ) {
    return incident.location;
  }

  const firstLinkedReport = linkedReports[0];
  if (
    firstLinkedReport?.location &&
    hasValidReportedLocation({
      latitude: firstLinkedReport.location.latitude,
      longitude: firstLinkedReport.location.longitude,
    })
  ) {
    return firstLinkedReport.location;
  }

  for (const report of linkedReports.slice(1)) {
    if (
      report.location &&
      hasValidReportedLocation({
        latitude: report.location.latitude,
        longitude: report.location.longitude,
      })
    ) {
      return report.location;
    }
  }

  return null;
}
