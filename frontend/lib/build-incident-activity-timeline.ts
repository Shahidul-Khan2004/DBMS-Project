import { formatIncidentField } from "@/lib/operations-incident-format";
import { sortNewestFirst } from "@/lib/sort";
import type {
  IncidentActivityTimelineItem,
  IncidentActivityTimelineKind,
  IncidentActivityTimelineTone,
  IncidentDetailResponse,
  IncidentDispatch,
  LinkedIntakeReport,
  ParticipatingAgency,
  TimelinePreviewItem,
} from "@/types/incident-command";

function joinDescription(parts: Array<string | null | undefined>) {
  return parts
    .map((part) => part?.trim())
    .filter((part): part is string => Boolean(part))
    .join(" · ");
}

function linkedReportTitle(linkType: string) {
  const key = linkType.trim().toLowerCase();
  switch (key) {
    case "primary_report":
      return "Primary report linked to incident";
    case "supporting_report":
      return "Supporting report linked to incident";
    case "follow_up_report":
      return "Follow-up report linked to incident";
    default:
      return `${formatIncidentField(linkType)} linked to incident`;
  }
}

function toneForKind(
  kind: IncidentActivityTimelineKind | string,
): IncidentActivityTimelineTone | undefined {
  switch (kind) {
    case "incident_reported":
      return "info";
    case "lead_agency_assigned":
    case "agency_assigned":
      return "info";
    case "dispatch_assigned":
    case "dispatch_dispatched":
      return "info";
    case "dispatch_arrived":
      return "success";
    case "dispatch_completed":
      return "success";
    case "dispatch_cancelled":
      return "danger";
    case "report_linked":
      return "neutral";
    case "operator_note":
      return "neutral";
    default:
      return "neutral";
  }
}

function badgeToneForKind(kind: IncidentActivityTimelineKind | string): string | undefined {
  switch (kind) {
    case "incident_reported":
      return "reported";
    case "lead_agency_assigned":
    case "agency_assigned":
      return "agency_assigned";
    case "dispatch_assigned":
      return "unit_assigned";
    case "dispatch_dispatched":
      return "dispatched";
    case "dispatch_arrived":
      return "in_progress";
    case "dispatch_completed":
      return "resolved";
    case "dispatch_cancelled":
      return "cancelled";
    default:
      return undefined;
  }
}

function buildIncidentReportedItem(
  detail: IncidentDetailResponse,
): IncidentActivityTimelineItem | null {
  if (!detail.reportedAt?.trim()) return null;

  return {
    key: "incident-reported",
    kind: "incident_reported",
    title: "Incident reported",
    description: detail.title,
    occurredAt: detail.reportedAt,
    badgeLabel: "Incident",
    tone: toneForKind("incident_reported"),
    badgeTone: badgeToneForKind("incident_reported"),
  };
}

function buildAgencyItems(agencies: ParticipatingAgency[]): IncidentActivityTimelineItem[] {
  const items: IncidentActivityTimelineItem[] = [];

  for (const agency of agencies) {
    if (!agency.joinedAt?.trim()) continue;

    const kind: IncidentActivityTimelineKind = agency.isLeadAgency
      ? "lead_agency_assigned"
      : "agency_assigned";

    items.push({
      key: `agency-${agency.agencyPublicUuid || agency.agencyName}-joined`,
      kind,
      title: agency.isLeadAgency
        ? `${agency.agencyName} assigned as lead agency`
        : `${agency.agencyName} assigned to response`,
      occurredAt: agency.joinedAt,
      badgeLabel: agency.isLeadAgency ? "Lead Agency" : "Agency Assigned",
      tone: toneForKind(kind),
      badgeTone: badgeToneForKind(kind),
    });
  }

  return items;
}

function buildDispatchAssignedItem(
  dispatch: IncidentDispatch,
): IncidentActivityTimelineItem | null {
  if (!dispatch.assignedAt?.trim()) return null;

  return {
    key: `dispatch-${dispatch.publicUuid}-assigned`,
    kind: "dispatch_assigned",
    title: `${dispatch.unitName} assigned for dispatch`,
    occurredAt: dispatch.assignedAt,
    badgeLabel: "Unit Assigned",
    tone: toneForKind("dispatch_assigned"),
    badgeTone: badgeToneForKind("dispatch_assigned"),
  };
}

function buildDispatchDispatchedItem(
  dispatch: IncidentDispatch,
): IncidentActivityTimelineItem | null {
  if (!dispatch.dispatchedAt?.trim()) return null;

  return {
    key: `dispatch-${dispatch.publicUuid}-dispatched`,
    kind: "dispatch_dispatched",
    title: `${dispatch.unitName} dispatched`,
    occurredAt: dispatch.dispatchedAt,
    badgeLabel: "Dispatched",
    tone: toneForKind("dispatch_dispatched"),
    badgeTone: badgeToneForKind("dispatch_dispatched"),
  };
}

function buildDispatchArrivedItem(
  dispatch: IncidentDispatch,
): IncidentActivityTimelineItem | null {
  if (!dispatch.arrivedAt?.trim()) return null;

  return {
    key: `dispatch-${dispatch.publicUuid}-arrived`,
    kind: "dispatch_arrived",
    title: `${dispatch.unitName} arrived at scene`,
    occurredAt: dispatch.arrivedAt,
    badgeLabel: "Arrived",
    tone: toneForKind("dispatch_arrived"),
    badgeTone: badgeToneForKind("dispatch_arrived"),
  };
}

function buildDispatchCompletedItem(
  dispatch: IncidentDispatch,
): IncidentActivityTimelineItem | null {
  if (!dispatch.completedAt?.trim()) return null;

  return {
    key: `dispatch-${dispatch.publicUuid}-completed`,
    kind: "dispatch_completed",
    title: `${dispatch.unitName} completed response`,
    occurredAt: dispatch.completedAt,
    badgeLabel: "Completed",
    tone: toneForKind("dispatch_completed"),
    badgeTone: badgeToneForKind("dispatch_completed"),
  };
}

function buildDispatchCancelledItem(
  dispatch: IncidentDispatch,
): IncidentActivityTimelineItem | null {
  if (!dispatch.cancelledAt?.trim()) return null;

  return {
    key: `dispatch-${dispatch.publicUuid}-cancelled`,
    kind: "dispatch_cancelled",
    title: `${dispatch.unitName} dispatch cancelled`,
    occurredAt: dispatch.cancelledAt,
    badgeLabel: "Cancelled",
    tone: toneForKind("dispatch_cancelled"),
    badgeTone: badgeToneForKind("dispatch_cancelled"),
  };
}

function buildDispatchItems(dispatches: IncidentDispatch[]): IncidentActivityTimelineItem[] {
  const items: IncidentActivityTimelineItem[] = [];

  for (const dispatch of dispatches) {
    const dispatchItems = [
      buildDispatchAssignedItem(dispatch),
      buildDispatchDispatchedItem(dispatch),
      buildDispatchArrivedItem(dispatch),
      buildDispatchCompletedItem(dispatch),
      buildDispatchCancelledItem(dispatch),
    ];

    for (const item of dispatchItems) {
      if (item) items.push(item);
    }
  }

  return items;
}

function buildLinkedReportItems(
  reports: LinkedIntakeReport[],
): IncidentActivityTimelineItem[] {
  const items: IncidentActivityTimelineItem[] = [];

  for (const report of reports) {
    if (!report.linkedAt?.trim()) continue;

    items.push({
      key: `report-${report.intakeReportCode}-${report.linkType}-linked`,
      kind: "report_linked",
      title: linkedReportTitle(report.linkType),
      description: joinDescription([report.intakeReportCode, report.summary]),
      occurredAt: report.linkedAt,
      badgeLabel: report.linkTypeLabel,
      tone: toneForKind("report_linked"),
      badgeTone: report.linkType,
    });
  }

  return items;
}

function buildPreviewItems(
  preview: TimelinePreviewItem[],
): IncidentActivityTimelineItem[] {
  return preview
    .filter((item) => item.eventTime?.trim())
    .map((item) => {
      const isOperatorNote = item.eventType === "operator_note";
      const kind: IncidentActivityTimelineKind | string = isOperatorNote
        ? "operator_note"
        : item.eventType;

      return {
        key: `preview-${item.id || item.eventTime}-${item.eventType}`,
        kind,
        title: item.eventTitle,
        description: item.eventDescription,
        occurredAt: item.eventTime,
        badgeLabel: isOperatorNote ? "Operator Note" : item.eventTypeLabel,
        tone: toneForKind(isOperatorNote ? "operator_note" : item.eventType),
        badgeTone: isOperatorNote ? undefined : item.eventType,
      };
    });
}

export function buildIncidentActivityTimeline(
  detail: IncidentDetailResponse,
): IncidentActivityTimelineItem[] {
  const items: IncidentActivityTimelineItem[] = [];

  const reported = buildIncidentReportedItem(detail);
  if (reported) items.push(reported);

  items.push(
    ...buildAgencyItems(detail.participatingAgencies),
    ...buildDispatchItems(detail.dispatches),
    ...buildLinkedReportItems(detail.linkedIntakeReports),
    ...buildPreviewItems(detail.timelinePreview),
  );

  return sortNewestFirst(items, (item) => [item.occurredAt]);
}
