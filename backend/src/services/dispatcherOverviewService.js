import {
  countIntakeReportsPendingClassification,
  listRecentIntakeReportsPendingClassification,
} from "../repositories/operationsIntakeRepo.js";
import {
  countActiveIncidentsForOperations,
  listRecentActiveIncidentsForOverview,
} from "../repositories/incidentOperationsRepo.js";
import {
  countOpenServiceCases,
  listRecentOpenServiceCasesForOperations,
} from "../repositories/operationsServiceCaseRepo.js";

const RECENT_PER_SOURCE = 10;
const RECENT_MERGED_MAX = 15;

/** @param {Date | string} value */
function occurredAtTimestamp(value) {
  if (!value) return 0;
  const t = value instanceof Date ? value.getTime() : new Date(value).getTime();
  return Number.isNaN(t) ? 0 : t;
}

/** @param {Date | string} value */
function toIsoOccurredAt(value) {
  if (!value) return "";
  const d = value instanceof Date ? value : new Date(value);
  const t = d.getTime();
  return Number.isNaN(t) ? "" : d.toISOString();
}

export async function getDispatcherOverviewPayload() {
  const [
    intake_reports_pending_classification,
    incidents_active,
    service_cases_open,
    intakeRows,
    incidentRows,
    caseRows,
  ] = await Promise.all([
    countIntakeReportsPendingClassification(),
    countActiveIncidentsForOperations(),
    countOpenServiceCases(),
    listRecentIntakeReportsPendingClassification(RECENT_PER_SOURCE),
    listRecentActiveIncidentsForOverview(RECENT_PER_SOURCE),
    listRecentOpenServiceCasesForOperations(RECENT_PER_SOURCE),
  ]);

  const merged = [];

  for (const row of intakeRows) {
    merged.push({
      kind: "intake_report",
      public_uuid: row.public_uuid,
      summary: row.summary ?? "",
      status: row.intake_status,
      category: row.category_code ?? "",
      occurred_at: toIsoOccurredAt(row.reported_at),
      age_minutes: Math.max(0, Math.floor(Number(row.age_minutes) || 0)),
      _ts: occurredAtTimestamp(row.reported_at),
    });
  }

  for (const row of incidentRows) {
    merged.push({
      kind: "incident",
      public_uuid: row.public_uuid,
      summary: row.title ?? "",
      status: row.status_code,
      category: row.category_code ?? "",
      occurred_at: toIsoOccurredAt(row.reported_at),
      age_minutes: Math.max(0, Math.floor(Number(row.age_minutes) || 0)),
      _ts: occurredAtTimestamp(row.reported_at),
    });
  }

  for (const row of caseRows) {
    merged.push({
      kind: "service_case",
      public_uuid: row.public_uuid,
      summary: row.title ?? "",
      status: row.status_code,
      category: row.category_code ?? "",
      occurred_at: toIsoOccurredAt(row.created_at),
      age_minutes: Math.max(0, Math.floor(Number(row.age_minutes) || 0)),
      _ts: occurredAtTimestamp(row.created_at),
    });
  }

  merged.sort((a, b) => b._ts - a._ts);
  const recent = merged.slice(0, RECENT_MERGED_MAX).map((item) => {
    const { _ts, ...rest } = item;
    return rest;
  });

  return {
    counts: {
      intake_reports_pending_classification,
      incidents_active,
      service_cases_open,
    },
    recent,
  };
}
