export interface OperationsIntakeReport {
  public_uuid: string;
  report_code: string;
  reporter_user_id: string;
  urgency_type: "non_emergency" | "emergency" | "unknown" | string;
  summary: string;
  description: string | null;
  intake_status: string;
  final_disposition: string | null;
  channel_code: string;
  category_code: string;
  location?: {
    public_uuid: string;
    latitude: number;
    longitude: number;
    address_text: string | null;
    place_name: string | null;
    admin_area_id: number | null;
    source: string;
  } | null;
  location_text?: string | null;
  has_service_case: boolean;
  has_incident: boolean;
  reported_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface OperationsIntakeReportsResponse {
  intake_reports: OperationsIntakeReport[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

export interface OperationsIntakeReportResponse {
  intake_report: OperationsIntakeReport;
}
