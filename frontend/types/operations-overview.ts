export type DispatcherOverviewRecentKind =
  | "intake_report"
  | "incident"
  | "service_case";

/** GET /operations/dispatcher/overview response */
export interface DispatcherOverviewResponse {
  counts: {
    intake_reports_pending_classification: number;
    incidents_active: number;
    service_cases_open: number;
  };
  recent: DispatcherOverviewRecentItem[];
}

export interface DispatcherOverviewRecentItem {
  kind: DispatcherOverviewRecentKind;
  public_uuid: string;
  summary: string;
  status: string;
  category: string;
  occurred_at: string;
  age_minutes: number;
}
