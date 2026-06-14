import { formatBadgeLabel } from "@/components/ui/Badge";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";
import {
  formatIncidentField,
  formatIncidentLinkType,
  formatIncidentLocationText,
  getIncidentReportedLocation,
} from "@/lib/operations-incident-format";
import { formatRelativeAge } from "@/lib/format-relative-age";
import { resolveIncidentSourceLabel } from "@/lib/incident-source-label";
import type { OperationsIntakeReport } from "@/types/operations-intake";
import type {
  IncidentDetailResponse,
  IncidentDispatch,
  IncidentListItem,
  IncidentLocation,
  IncidentOverview,
  LinkedIntakeReport,
  ParticipatingAgency,
  TimelinePreviewItem,
} from "@/types/incident-command";
import type {
  OperationsIncidentDetailResponse,
  OperationsIncidentDispatch,
  OperationsLinkedIntakeReport,
  OperationsParticipatingAgency,
  OperationsTimelineEvent,
} from "@/types/operations-incident";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";

function mapLocation(
  location: ReturnType<typeof getIncidentReportedLocation>,
): IncidentLocation | null {
  if (!location) return null;
  return {
    latitude: location.latitude,
    longitude: location.longitude,
    addressText: location.address_text,
    placeName: location.place_name,
    adminAreaId: location.admin_area_id ?? null,
  };
}

export function mapOperationsIncidentRowToListItem(
  row: OperationsIncidentRow,
): IncidentListItem | null {
  if (!row.public_uuid?.trim()) return null;

  const locationFromApi =
    row.location?.address_text?.trim() ||
    row.location?.place_name?.trim() ||
    row.location_text?.trim() ||
    "";

  return {
    publicUuid: row.public_uuid,
    incidentCode: row.incident_code?.trim() || "Unknown code",
    title: row.title?.trim() || "Untitled incident",
    categoryLabel: row.category_code
      ? formatBadgeLabel(row.category_code)
      : "-",
    severity: row.severity_code?.trim() || "medium",
    status: row.status_code?.trim() || "classified",
    locationText: locationFromApi || "Location unavailable",
    reportedAt: row.reported_at ?? "",
  };
}

function mapParticipatingAgency(agency: OperationsParticipatingAgency): ParticipatingAgency {
  return {
    agencyPublicUuid: agency.agency_public_uuid?.trim() || "",
    agencyName: agency.agency_name?.trim() || "Unknown agency",
    agencyTypeLabel: formatIncidentField(agency.agency_type_code),
    isLeadAgency: Boolean(agency.is_lead_agency),
    participationStatus: agency.participation_status,
    participationStatusLabel: formatIncidentField(agency.participation_status),
    joinedAt: agency.joined_at,
  };
}

function mapDispatch(dispatch: OperationsIncidentDispatch): IncidentDispatch {
  return {
    publicUuid: dispatch.public_uuid?.trim() || "",
    unitName: dispatch.unit?.unit_name?.trim() || "Unknown unit",
    unitCode: dispatch.unit?.unit_code?.trim() || "-",
    unitTypeLabel: formatIncidentField(dispatch.unit?.unit_type_code),
    owningAgencyName:
      dispatch.owning_agency?.agency_name?.trim() || "Unknown agency",
    dispatchStatus: dispatch.status_code,
    dispatchStatusLabel: formatIncidentField(dispatch.status_code),
    priorityLevel: dispatch.priority_level,
    priorityLevelLabel: formatIncidentField(dispatch.priority_level),
    assignedAt: dispatch.assigned_at,
    dispatchedAt: dispatch.dispatched_at,
    arrivedAt: dispatch.arrived_at,
    completedAt: dispatch.completed_at,
    cancelledAt: dispatch.cancelled_at,
  };
}

function mapLinkedIntakeReport(report: OperationsLinkedIntakeReport): LinkedIntakeReport {
  return {
    intakePublicUuid: report.intake_public_uuid?.trim() || "",
    intakeReportCode: report.intake_report_code?.trim() || "-",
    summary: report.intake_summary?.trim() || "-",
    linkType: report.link_type,
    linkTypeLabel: formatIncidentLinkType(report.link_type),
    linkedAt: report.linked_at,
    linkNote: report.link_note?.trim() || null,
  };
}

export function getPrimaryLinkedIntakeReportFromDetail(
  detail: Pick<IncidentDetailResponse, "linkedIntakeReports">,
): LinkedIntakeReport | undefined {
  return detail.linkedIntakeReports.find(
    (report) =>
      report.linkType?.trim().toLowerCase() === "primary_report",
  );
}

export function getLocationSourceLinkedIntakeReport(
  detail: Pick<IncidentDetailResponse, "linkedIntakeReports">,
): LinkedIntakeReport | null {
  return detail.linkedIntakeReports[0] ?? null;
}

export function getLocationSourceReportUuid(
  detail: Pick<IncidentDetailResponse, "linkedIntakeReports">,
): string | null {
  const uuid = getLocationSourceLinkedIntakeReport(detail)?.intakePublicUuid?.trim();
  return uuid || null;
}

export function getIncidentDisplayLocationFromDetail(
  detail: Pick<IncidentDetailResponse, "overview">,
): {
  addressText: string | null;
  location: IncidentLocation | null;
} {
  const addressText = detail.overview.locationText?.trim() || null;
  return {
    addressText,
    location: detail.overview.location ?? null,
  };
}

export function deriveIncidentSourceLabel(
  detail: Pick<IncidentDetailResponse, "linkedIntakeReports" | "overview">,
  sourceIntakeDetail?: OperationsIntakeReport | null,
): string {
  return resolveIncidentSourceLabel({
    sourceLinkedReport: getLocationSourceLinkedIntakeReport(detail),
    sourceIntakeDetail,
    incidentOriginType: detail.overview.originType,
  });
}

export function mapIncidentDetailToLocationEditItem(
  detail: IncidentDetailResponse,
): IntakeQueueItem | null {
  const locationSourceReport = getLocationSourceLinkedIntakeReport(detail);
  const reportPublicUuid = locationSourceReport?.intakePublicUuid?.trim();
  if (!reportPublicUuid) return null;

  const location = detail.overview.location;

  return {
    id: reportPublicUuid,
    reportCode: reportPublicUuid,
    status: "under_review",
    summary: locationSourceReport?.summary?.trim() || detail.title,
    category: detail.categoryLabel,
    description: detail.overview.description?.trim() || "",
    channel: "",
    ageLabel: detail.reportedAgeLabel,
    receivedMinutesAgo: 0,
    location: {
      addressText: location?.addressText?.trim() || "",
      areaName: location?.placeName?.trim() || "",
      districtName: "",
      adminAreaId: location?.adminAreaId ?? null,
      latitude: location?.latitude,
      longitude: location?.longitude,
    },
  };
}

function mapTimelineItem(event: OperationsTimelineEvent): TimelinePreviewItem {
  return {
    id: event.id?.trim() || event.event_time,
    eventTitle: event.event_title?.trim() || "Event",
    eventDescription: event.event_description,
    eventType: event.event_type,
    eventTypeLabel: formatIncidentField(event.event_type),
    eventTime: event.event_time,
  };
}

export function mapOperationsIncidentDetailResponse(
  api: OperationsIncidentDetailResponse,
): IncidentDetailResponse {
  const incident = api.incident;
  const linkedReports = api.linked_intake_reports ?? [];
  const linkedIntakeReports = linkedReports.map(mapLinkedIntakeReport);
  const primaryLinkedReport =
    getPrimaryLinkedIntakeReportFromDetail({ linkedIntakeReports });
  const primaryIntakePublicUuid =
    primaryLinkedReport?.intakePublicUuid?.trim() || null;
  const primaryIntakeSummary = primaryLinkedReport?.summary?.trim() || null;
  const resolvedLocation = getIncidentReportedLocation(incident, linkedReports);
  const locationText = formatIncidentLocationText(resolvedLocation);

  const overview: IncidentOverview = {
    title: incident.title?.trim() || "Untitled incident",
    description: incident.description,
    categoryLabel: formatIncidentField(incident.category_code),
    severity: incident.severity_code?.trim() || "medium",
    originType: incident.origin_type?.trim() || "",
    reportedAt: incident.reported_at,
    status: incident.status_code?.trim() || "classified",
    locationText,
    location: mapLocation(resolvedLocation),
  };

  return {
    incidentCode: incident.incident_code?.trim() || "Unknown code",
    title: overview.title,
    severity: overview.severity,
    status: overview.status,
    categoryLabel: overview.categoryLabel,
    reportedAt: incident.reported_at,
    reportedAgeLabel: formatRelativeAge(incident.reported_at),
    primaryIntakePublicUuid,
    primaryIntakeSummary,
    overview,
    participatingAgencies: (api.participating_agencies ?? []).map(
      mapParticipatingAgency,
    ),
    dispatches: (api.dispatches ?? []).map(mapDispatch),
    linkedIntakeReports,
    timelinePreview: (api.timeline_preview ?? []).map(mapTimelineItem),
  };
}
