import BackendError from "../lib/BackendError.js";
import { query } from "../config/db.js";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

function formatReporterRiskRow(row, compact = false) {
  const base = {
    reporter_public_uuid: row.reporter_public_uuid,
    reporter_full_name: row.reporter_full_name,
    account_status: row.account_status,
    account_status_expires_at: row.account_status_expires_at ?? null,
    total_reports: Number(row.total_reports ?? 0),
    false_alarm_reports: Number(row.false_alarm_reports ?? 0),
    malicious_false_reports: Number(row.malicious_false_reports ?? 0),
    false_reports_30d: Number(row.false_reports_30d ?? 0),
    risk_level: row.risk_level,
  };

  if (compact) {
    return base;
  }

  return {
    ...base,
    reporter_email: row.reporter_email,
    reporter_phone_number: row.reporter_phone_number,
    reviewed_reports: Number(row.reviewed_reports ?? 0),
    genuine_reports: Number(row.genuine_reports ?? 0),
    duplicate_reports: Number(row.duplicate_reports ?? 0),
    mistaken_reports: Number(row.mistaken_reports ?? 0),
    unverified_reports: Number(row.unverified_reports ?? 0),
    malicious_false_reports_30d: Number(row.malicious_false_reports_30d ?? 0),
    latest_false_report_at: row.latest_false_report_at,
    latest_report_at: row.latest_report_at,
  };
}

function buildRiskListOrder(sort) {
  switch (sort) {
    case "false_reports_30d_desc":
      return "false_reports_30d DESC, malicious_false_reports DESC, total_reports DESC";
    case "total_reports_desc":
      return "total_reports DESC, false_reports_30d DESC";
    case "latest_false_report_desc":
      return "latest_false_report_at IS NULL, latest_false_report_at DESC";
    case "risk_desc":
    default:
      return `
        FIELD(risk_level, 'high', 'medium', 'low'),
        false_reports_30d DESC,
        malicious_false_reports DESC,
        total_reports DESC
      `;
  }
}

export async function findReporterRiskByUserId(reporterUserId, { compact = false } = {}) {
  if (!reporterUserId) return null;

  const { rows } = await query(
    `
      SELECT *
      FROM vw_reporter_reliability
      WHERE reporter_user_id = ?
      LIMIT 1
    `,
    [reporterUserId],
  );

  if (!rows[0]) return null;
  return formatReporterRiskRow(rows[0], compact);
}

export async function findReporterRiskByPublicUuid(publicUuid) {
  const { rows } = await query(
    `
      SELECT *
      FROM vw_reporter_reliability
      WHERE reporter_public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );

  if (!rows[0]) {
    throw new BackendError(404, "USER_NOT_FOUND", "Reporter not found");
  }

  return formatReporterRiskRow(rows[0]);
}

export async function listReporterRisks(filters) {
  const limit = Math.min(
    Math.max(Number(filters.limit) || DEFAULT_LIMIT, 1),
    MAX_LIMIT,
  );
  const offset = Math.max(Number(filters.offset) || 0, 0);
  const params = [];
  const clauses = [];

  if (filters.riskLevel) {
    clauses.push("risk_level = ?");
    params.push(filters.riskLevel);
  }
  if (filters.accountStatus) {
    clauses.push("account_status = ?");
    params.push(filters.accountStatus);
  }

  const whereSql = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const orderSql = buildRiskListOrder(filters.sort);

  const countResult = await query(
    `SELECT COUNT(*) AS cnt FROM vw_reporter_reliability ${whereSql}`,
    params,
  );
  const total =
    typeof countResult.rows[0]?.cnt === "bigint"
      ? Number(countResult.rows[0].cnt)
      : Number(countResult.rows[0]?.cnt ?? 0);

  const listResult = await query(
    `
      SELECT *
      FROM vw_reporter_reliability
      ${whereSql}
      ORDER BY ${orderSql}
      LIMIT ?
      OFFSET ?
    `,
    [...params, limit, offset],
  );

  return {
    reporters: listResult.rows.map((row) => ({
      reporter_public_uuid: row.reporter_public_uuid,
      reporter_full_name: row.reporter_full_name,
      reporter_email: row.reporter_email,
      reporter_phone_number: row.reporter_phone_number,
      account_status: row.account_status,
      total_reports: Number(row.total_reports ?? 0),
      reviewed_reports: Number(row.reviewed_reports ?? 0),
      false_alarm_reports: Number(row.false_alarm_reports ?? 0),
      malicious_false_reports: Number(row.malicious_false_reports ?? 0),
      false_reports_30d: Number(row.false_reports_30d ?? 0),
      malicious_false_reports_30d: Number(row.malicious_false_reports_30d ?? 0),
      latest_false_report_at: row.latest_false_report_at,
      risk_level: row.risk_level,
    })),
    pagination: { limit, offset, total },
  };
}

export async function getReporterRiskSummaryCounts() {
  const { rows } = await query(
    `
      SELECT
        SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) AS high_risk_count,
        SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) AS medium_risk_count,
        SUM(CASE WHEN account_status = 'suspended' THEN 1 ELSE 0 END) AS suspended_count,
        SUM(malicious_false_reports_30d) AS malicious_false_reports_30d_total
      FROM vw_reporter_reliability
    `,
    [],
  );

  const row = rows[0] ?? {};
  return {
    high_risk_count: Number(row.high_risk_count ?? 0),
    medium_risk_count: Number(row.medium_risk_count ?? 0),
    suspended_count: Number(row.suspended_count ?? 0),
    malicious_false_reports_30d_total: Number(row.malicious_false_reports_30d_total ?? 0),
  };
}

export async function listRecentVerificationsForReporter(reporterUserId, limit = 10) {
  if (!reporterUserId) return [];

  const capped = Math.min(Math.max(Number(limit) || 10, 1), 25);
  const { rows } = await query(
    `
      SELECT
        ir.public_uuid AS intake_report_public_uuid,
        ir.report_code,
        ir.summary,
        lv.verdict,
        lv.confidence_level,
        lv.created_at
      FROM intake_reports ir
      INNER JOIN (
        SELECT intake_report_id, verdict, confidence_level, created_at
        FROM (
          SELECT
            intake_report_id,
            verdict,
            confidence_level,
            created_at,
            ROW_NUMBER() OVER (
              PARTITION BY intake_report_id
              ORDER BY created_at DESC, id DESC
            ) AS rn
          FROM intake_report_verification_reviews
        ) ranked
        WHERE rn = 1
      ) lv ON lv.intake_report_id = ir.id
      WHERE ir.reporter_user_id = ?
      ORDER BY lv.created_at DESC
      LIMIT ?
    `,
    [reporterUserId, capped],
  );

  return rows.map((row) => ({
    intake_report_public_uuid: row.intake_report_public_uuid,
    report_code: row.report_code,
    summary: row.summary,
    verdict: row.verdict,
    confidence_level: row.confidence_level,
    created_at: row.created_at,
  }));
}

export async function listRecentReportsForReporter(reporterUserId, limit = 15) {
  const capped = Math.min(Math.max(Number(limit) || 15, 1), 50);
  const { rows } = await query(
    `
      SELECT
        ir.public_uuid AS intake_report_public_uuid,
        ir.report_code,
        ir.summary,
        ist.status_code AS intake_status,
        rcat.category_code,
        ir.reported_at,
        lv.verdict AS latest_verdict,
        lv.confidence_level AS latest_confidence_level
      FROM intake_reports ir
      INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
      INNER JOIN report_categories rcat ON rcat.id = ir.category_id
      LEFT JOIN (
        SELECT intake_report_id, verdict, confidence_level
        FROM (
          SELECT
            intake_report_id,
            verdict,
            confidence_level,
            ROW_NUMBER() OVER (
              PARTITION BY intake_report_id
              ORDER BY created_at DESC, id DESC
            ) AS rn
          FROM intake_report_verification_reviews
        ) ranked
        WHERE rn = 1
      ) lv ON lv.intake_report_id = ir.id
      WHERE ir.reporter_user_id = ?
      ORDER BY ir.reported_at DESC
      LIMIT ?
    `,
    [reporterUserId, capped],
  );

  return rows.map((row) => ({
    intake_report_public_uuid: row.intake_report_public_uuid,
    report_code: row.report_code,
    summary: row.summary,
    intake_status: row.intake_status,
    category_code: row.category_code,
    reported_at: row.reported_at,
    latest_verdict: row.latest_verdict,
    latest_confidence_level: row.latest_confidence_level,
  }));
}

export async function resolveReporterUserIdByPublicUuid(publicUuid) {
  const { rows } = await query(
    `SELECT id FROM users WHERE public_uuid = ? LIMIT 1`,
    [publicUuid],
  );
  return rows[0]?.id ?? null;
}
