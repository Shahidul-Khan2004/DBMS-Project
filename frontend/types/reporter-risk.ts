export type ReporterRiskLevel = "low" | "medium" | "high";

export type ReporterRiskSummary = {
  reporter_public_uuid: string;
  reporter_full_name: string;
  reporter_email?: string;
  reporter_phone_number?: string;
  account_status: string;
  account_status_expires_at?: string | null;
  total_reports: number;
  reviewed_reports?: number;
  genuine_reports?: number;
  duplicate_reports?: number;
  mistaken_reports?: number;
  unverified_reports?: number;
  false_alarm_reports: number;
  malicious_false_reports: number;
  false_reports_30d: number;
  malicious_false_reports_30d?: number;
  latest_false_report_at?: string | null;
  latest_report_at?: string | null;
  risk_level: ReporterRiskLevel;
};

export type IntakeLatestVerification = {
  verdict: string;
  confidence_level: string;
  reason?: string | null;
  created_at: string;
};

export type VerificationVerdict =
  | "genuine"
  | "duplicate"
  | "mistaken"
  | "unverified"
  | "false_alarm"
  | "malicious_false_report";

export type RecordVerificationPayload = {
  verdict: VerificationVerdict;
  reason?: string;
  evidenceNote?: string;
  confidenceLevel?: "low" | "medium" | "high";
};

export type ReporterRecentVerification = {
  intake_report_public_uuid: string;
  report_code: string;
  summary: string;
  verdict: string;
  confidence_level: string;
  created_at: string;
};

export type ReporterRecentReport = {
  intake_report_public_uuid: string;
  report_code: string;
  summary: string;
  intake_status: string;
  category_code: string;
  reported_at: string;
  latest_verdict: string | null;
  latest_confidence_level: string | null;
};

export type ReporterAccountAction = {
  public_uuid: string;
  action_type: string;
  previous_account_status: string | null;
  new_account_status: string | null;
  reason: string;
  suspension_ends_at?: string | null;
  created_at: string;
  action_by?: {
    public_uuid: string;
    full_name: string;
  };
};

export type AdminAccountActionPayload = {
  accountStatus: "active" | "suspended" | "disabled";
  reason: string;
  suspensionDays?: number;
  suspendedUntil?: string;
};

export type AdminReporterNotePayload = {
  actionType: "warning" | "note";
  reason: string;
};
