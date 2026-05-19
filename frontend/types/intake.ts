export interface IntakeReport {
  public_uuid: string;
  report_code: string;
  summary: string;
  description: string | null;
  urgency_type: "non_emergency" | "emergency" | "unknown";
  intake_status:
    | "received"
    | "under_review"
    | "linked_to_case"
    | "linked_to_incident"
    | "resolved"
    | "duplicate"
    | "false_report"
    | "cancelled"
    | "closed";
  final_disposition: string | null;
  reported_at: string | null;
  created_at: string;
  updated_at?: string;
  channel_code: string;
  category_code: string;
  location_text: string | null;
  location?: IntakeLocation | null;
  incident_public_uuid: string | null;
  incident_code: string | null;
  incident_status_code: string | null;
  incident_is_terminal: 0 | 1 | boolean | null;
  incident_resolved_at: string | null;
}

export interface IntakeReportDetailResponse {
  report: IntakeReport;
}

export interface IntakeReportListResponse {
  reports: IntakeReport[];
}

export interface IntakeReportStats {
  totalReports: number;
  pendingReports: number;
  resolvedReports: number;
}

export interface IntakeReportStatsResponse {
  stats: IntakeReportStats;
}

export type IntakeLocationSource =
  | "user_shared"
  | "dispatcher_selected"
  | "api_geocoded"
  | "manual_entry";

/** Structured `location` on create intake / operations (matches backend `locationObjectSchema`). */
export interface IntakeStructuredLocation {
  latitude: number;
  longitude: number;
  address_text?: string;
  place_name?: string;
  admin_area_id?: number;
  source?: IntakeLocationSource;
}

export interface IntakeLocation {
  public_uuid: string;
  latitude: number;
  longitude: number;
  address_text: string | null;
  place_name: string | null;
  admin_area_id: number | null;
  source: IntakeLocationSource | string;
}

export interface IntakeLocationHistoryItem {
  change_kind: "initial_create" | "location_patch" | string;
  location: IntakeLocation | null;
  previous_location: IntakeLocation | null;
  changed_by: {
    public_uuid: string;
    full_name: string;
    actor_kind: "dispatcher" | "citizen" | string;
  } | null;
  changed_at: string;
}

export interface IntakeLocationHistoryResponse {
  history: IntakeLocationHistoryItem[];
}

export interface UpdateIntakeLocationResponse {
  message: string;
  report: IntakeReport;
}

export interface CreateIntakeReportRequest {
  channelCode: string;
  categoryCode: string;
  summary: string;
  description?: string;
  urgencyType?: "non_emergency" | "emergency" | "unknown";
  reportedAt?: string;
  location?: IntakeStructuredLocation;
  locationId?: string;
}

export interface CreateIntakeReportResponse {
  message: string;
  intake: IntakeReport;
}
