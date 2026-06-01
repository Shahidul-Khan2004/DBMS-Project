import { apiGet, apiPatch, apiPost } from "@/lib/api";
import type {
  IntakeEscalatePayload,
  IntakeEscalateResponse,
  OperationsServiceCaseListResponse,
  PatchServiceCaseStatusPayload,
  PostServiceCaseMessagePayload,
  PostServiceCaseResolvePayload,
  ServiceCaseDetailResponse,
  ServiceCaseMessageResponse,
} from "@/types/service-case";

export type ListOperationsServiceCasesQuery = {
  status?: string;
  categoryCode?: string;
  assignedTo?: string;
  limit?: number;
  offset?: number;
};

export async function listOperationsServiceCases(
  query: ListOperationsServiceCasesQuery = {},
): Promise<OperationsServiceCaseListResponse> {
  const search = new URLSearchParams({
    limit: String(query.limit ?? 50),
    offset: String(query.offset ?? 0),
  });

  if (query.status) {
    search.set("status", query.status);
  }
  if (query.categoryCode) {
    search.set("categoryCode", query.categoryCode);
  }
  if (query.assignedTo) {
    search.set("assignedTo", query.assignedTo);
  }

  return apiGet<OperationsServiceCaseListResponse>(
    `/operations/service-cases?${search.toString()}`,
  );
}

export function getOperationsServiceCaseDetail(publicUuid: string) {
  return apiGet<ServiceCaseDetailResponse>(
    `/operations/service-cases/${encodeURIComponent(publicUuid)}`,
  );
}

export function patchOperationsServiceCaseStatus(
  publicUuid: string,
  payload: PatchServiceCaseStatusPayload,
) {
  return apiPatch<ServiceCaseDetailResponse>(
    `/operations/service-cases/${encodeURIComponent(publicUuid)}/status`,
    payload,
  );
}

export function postOperationsServiceCaseMessage(
  publicUuid: string,
  payload: PostServiceCaseMessagePayload,
) {
  return apiPost<ServiceCaseMessageResponse>(
    `/operations/service-cases/${encodeURIComponent(publicUuid)}/messages`,
    payload,
  );
}

export function postOperationsServiceCaseResolve(
  publicUuid: string,
  payload: PostServiceCaseResolvePayload,
) {
  return apiPost<ServiceCaseDetailResponse>(
    `/operations/service-cases/${encodeURIComponent(publicUuid)}/resolve`,
    payload,
  );
}

export function postIntakeReportEscalate(
  intakePublicUuid: string,
  payload: IntakeEscalatePayload,
) {
  return apiPost<IntakeEscalateResponse>(
    `/intake/reports/${encodeURIComponent(intakePublicUuid)}/escalate`,
    payload,
  );
}
