export type IntakeLocation = {
  addressText: string;
  areaName: string;
  districtName: string;
  latitude?: number;
  longitude?: number;
};

export type IntakeQueueItem = {
  id: string;
  reportCode: string;
  status: "received" | "under_review";
  summary: string;
  category: string;
  description: string;
  channel: string;
  ageLabel: string;
  location: IntakeLocation;
  /** Internal sort key only — not displayed in UI */
  receivedMinutesAgo: number;
};

export type TriageStatusFilter = "all" | "received" | "under_review";

export type TriageCategoryFilter =
  | "all"
  | "fire"
  | "medical"
  | "infrastructure_emergency"
  | "crime_public_safety";

export type TriageSortOrder = "newest" | "oldest";

export type TriageQueueFilters = {
  status: TriageStatusFilter;
  category: TriageCategoryFilter;
  sort: TriageSortOrder;
};

export type RouteMode =
  | "options"
  | "service_case"
  | "emergency_incident"
  | "existing_incident"
  | "success_service_case"
  | "success_emergency_incident"
  | "success_existing_incident";

export type ActiveIncidentOption = {
  id: string;
  incidentCode: string;
  title: string;
  categoryLabel?: string;
  locationText: string;
  statusLabel: string;
  severityLabel?: string;
  reportedAgeLabel?: string;
};

export type ServiceCasePriority = "low" | "medium" | "high" | "urgent";

export type ServiceCaseDraft = {
  title: string;
  description: string;
  priority: ServiceCasePriority;
};

export type EmergencySeverity = "low" | "medium" | "high" | "critical";

export type EmergencyDraft = {
  severity: EmergencySeverity;
  title: string;
  description: string;
};

export type LinkType = "supporting_report" | "follow_up_report";

export type LinkDraft = {
  incidentId: string;
  linkType: LinkType;
  note: string;
};

export type RouteResult =
  | {
      kind: "service_case";
      publicUuid: string;
      caseCode: string;
      title: string;
      priority: ServiceCasePriority;
      statusCode: string;
    }
  | {
      kind: "emergency_incident";
      publicUuid: string;
      incidentCode: string;
      title: string;
      severity: EmergencySeverity;
      statusCode: string;
    }
  | {
      kind: "existing_incident";
      publicUuid: string;
      incidentCode: string;
      incidentTitle: string;
      linkType: LinkType;
    };
