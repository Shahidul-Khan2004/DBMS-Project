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
    | "duplicate"
    | "false_report"
    | "closed";
  final_disposition: string | null;
  reported_at: string | null;
  created_at: string;
  channel_code: string;
  category_code: string;
  location_text: string | null;
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

export interface CreateIntakeReportRequest {
  channelCode: string;
  categoryCode: string;
  summary: string;
  description?: string;
  urgencyType?: "non_emergency" | "unknown";
  reportedAt?: string;
  location?: string;
}

export interface CreateIntakeReportResponse {
  message: string;
  intake: IntakeReport;
}
