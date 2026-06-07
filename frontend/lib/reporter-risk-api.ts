import { ApiError, apiGet, apiPatch, apiPost } from "@/lib/api";
import type {
  AdminAccountActionPayload,
  AdminReporterNotePayload,
  RecordVerificationPayload,
  ReporterAccountAction,
  ReporterRecentReport,
  ReporterRecentVerification,
  ReporterRiskSummary,
} from "@/types/reporter-risk";

export async function fetchIntakeReporterRisk(reportPublicUuid: string) {
  const data = await apiGet<{
    reporter_risk: ReporterRiskSummary | null;
    recent_verifications: ReporterRecentVerification[];
  }>(`/operations/intake-reports/${encodeURIComponent(reportPublicUuid)}/reporter-risk`);
  return data;
}

export async function submitIntakeVerification(
  reportPublicUuid: string,
  payload: RecordVerificationPayload,
) {
  const data = await apiPost<{
    message: string;
    verification: Record<string, unknown>;
    reporter_risk: ReporterRiskSummary | null;
  }>(
    `/operations/intake-reports/${encodeURIComponent(reportPublicUuid)}/verification`,
    payload,
  );
  return data;
}

export type AdminReporterRiskListParams = {
  riskLevel?: "low" | "medium" | "high";
  accountStatus?: string;
  limit?: number;
  offset?: number;
  sort?: string;
};

export async function fetchAdminReporterRisks(params: AdminReporterRiskListParams = {}) {
  const search = new URLSearchParams();
  if (params.riskLevel) search.set("riskLevel", params.riskLevel);
  if (params.accountStatus) search.set("accountStatus", params.accountStatus);
  if (params.limit != null) search.set("limit", String(params.limit));
  if (params.offset != null) search.set("offset", String(params.offset));
  if (params.sort) search.set("sort", params.sort);
  const qs = search.toString();
  return apiGet<{
    reporters: ReporterRiskSummary[];
    pagination: { limit: number; offset: number; total: number };
  }>(`/admin/reporters/risk${qs ? `?${qs}` : ""}`);
}

export async function fetchAdminReporterRiskDetail(userPublicUuid: string) {
  return apiGet<{
    reporter_risk: ReporterRiskSummary;
    recent_reports: ReporterRecentReport[];
    account_actions: ReporterAccountAction[];
  }>(`/admin/reporters/${encodeURIComponent(userPublicUuid)}/risk`);
}

export async function patchAdminUserAccountStatus(
  userPublicUuid: string,
  payload: AdminAccountActionPayload,
) {
  return apiPatch<{
    message: string;
    user: Record<string, unknown>;
    account_action: ReporterAccountAction;
  }>(`/admin/users/${encodeURIComponent(userPublicUuid)}/account-status`, payload);
}

export async function postAdminReporterAction(
  userPublicUuid: string,
  payload: AdminReporterNotePayload,
) {
  return apiPost<{ message: string; account_action: ReporterAccountAction }>(
    `/admin/reporters/${encodeURIComponent(userPublicUuid)}/actions`,
    payload,
  );
}

export function getReporterRiskErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    return err.message || fallback;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return fallback;
}

export const VERDICT_OPTIONS: Array<{
  value: RecordVerificationPayload["verdict"];
  label: string;
}> = [
  { value: "genuine", label: "Genuine report" },
  { value: "duplicate", label: "Duplicate report" },
  { value: "mistaken", label: "Mistaken report" },
  { value: "unverified", label: "Unverified / inconclusive" },
  { value: "false_alarm", label: "False alarm" },
  { value: "malicious_false_report", label: "Malicious false report" },
];

export const CONFIDENCE_OPTIONS = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
] as const;

export function formatRiskLevelLabel(level: string): string {
  if (level === "high") return "High";
  if (level === "medium") return "Medium";
  return "Low";
}
