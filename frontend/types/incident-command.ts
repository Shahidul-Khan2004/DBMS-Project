export type IncidentLocation = {
  latitude: number;
  longitude: number;
  addressText: string | null;
  placeName: string | null;
  adminAreaId: number | null;
};

export type IncidentListItem = {
  publicUuid: string;
  incidentCode: string;
  title: string;
  categoryLabel: string;
  severity: string;
  status: string;
  locationText: string;
  reportedAt: string;
};

export type IncidentOverview = {
  title: string;
  description: string | null;
  categoryLabel: string;
  severity: string;
  originType: string;
  reportedAt: string | null;
  status: string;
  locationText: string | null;
  location: IncidentLocation | null;
};

export type ParticipatingAgency = {
  agencyPublicUuid: string;
  agencyName: string;
  agencyTypeLabel: string;
  isLeadAgency: boolean;
  participationStatus: string;
  participationStatusLabel: string;
  joinedAt: string;
};

export type DispatchPriorityLevel = "low" | "medium" | "high" | "critical";

export type DispatchStatusAction = "dispatched" | "arrived" | "completed" | "cancelled";

export type IncidentDispatch = {
  publicUuid: string;
  unitName: string;
  unitCode: string;
  unitTypeLabel: string;
  owningAgencyName: string;
  dispatchStatus: string;
  dispatchStatusLabel: string;
  priorityLevel: string;
  priorityLevelLabel: string;
  assignedAt: string | null;
  dispatchedAt: string | null;
  arrivedAt: string | null;
  completedAt: string | null;
  cancelledAt: string | null;
};

export type LinkedIntakeReport = {
  intakePublicUuid: string;
  intakeReportCode: string;
  summary: string;
  linkType: string;
  linkTypeLabel: string;
  linkedAt: string;
  linkNote: string | null;
};

export type TimelinePreviewItem = {
  id: string;
  eventTitle: string;
  eventDescription: string | null;
  eventType: string;
  eventTypeLabel: string;
  eventTime: string;
};

export type IncidentActivityTimelineKind =
  | "incident_reported"
  | "agency_assigned"
  | "lead_agency_assigned"
  | "dispatch_assigned"
  | "dispatch_dispatched"
  | "dispatch_arrived"
  | "dispatch_completed"
  | "dispatch_cancelled"
  | "report_linked"
  | "operator_note";

export type IncidentActivityTimelineTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "danger";

export type IncidentActivityTimelineItem = {
  key: string;
  kind: IncidentActivityTimelineKind | string;
  title: string;
  description?: string | null;
  occurredAt: string;
  badgeLabel: string;
  tone?: IncidentActivityTimelineTone;
  badgeTone?: string;
};

export type IncidentDetailResponse = {
  incidentCode: string;
  title: string;
  severity: string;
  status: string;
  categoryLabel: string;
  reportedAt: string | null;
  reportedAgeLabel: string;
  primaryIntakePublicUuid: string | null;
  primaryIntakeSummary: string | null;
  overview: IncidentOverview;
  participatingAgencies: ParticipatingAgency[];
  dispatches: IncidentDispatch[];
  linkedIntakeReports: LinkedIntakeReport[];
  timelinePreview: TimelinePreviewItem[];
};
