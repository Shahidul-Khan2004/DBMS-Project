export interface OperationsIntakeReporter {
  user_public_uuid: string | null;
  full_name: string | null;
  phone_number: string | null;
  email: string | null;
  is_anonymous: boolean;
}

export interface OperationsEmergencyCall {
  caller_phone_number: string | null;
}

export interface OperationsIntakeReport {
  public_uuid: string;
  report_code: string;
  reporter_user_id: string | null;
  /** Not returned by operations list mapper; optional for legacy UI. */
  urgency_type?: string;
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
    source: string | null;
  } | null;
  /** Present on GET /operations/intake-reports/:uuid detail only. */
  reporter?: OperationsIntakeReporter | null;
  /** Present on GET /operations/intake-reports/:uuid detail only. */
  emergency_call?: OperationsEmergencyCall | null;
  latest_verification?: {
    verdict: string;
    confidence_level: string;
    reason?: string | null;
    created_at: string;
  } | null;
  reporter_risk?: import("@/types/reporter-risk").ReporterRiskSummary | null;
  /** Not returned by operations mapper; optional for legacy UI. */
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
