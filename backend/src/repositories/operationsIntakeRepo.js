import BackendError from "../lib/BackendError.js";
import { query } from "../config/db.js";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

function buildListWhere(filters, params) {
  const clauses = [];

  if (filters.intake_status) {
    clauses.push("ir.intake_status = ?");
    params.push(filters.intake_status);
  }
  if (filters.urgency_type) {
    clauses.push("ir.urgency_type = ?");
    params.push(filters.urgency_type);
  }
  if (filters.categoryCode) {
    clauses.push("rcat.category_code = ?");
    params.push(filters.categoryCode);
  }

  const whereSql = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  return whereSql;
}

const INTAKE_SELECT = `
  SELECT
    ir.public_uuid AS public_uuid,
    ir.report_code AS report_code,
    ir.reporter_user_id AS reporter_user_id,
    ir.urgency_type AS urgency_type,
    ir.summary AS summary,
    ir.description AS description,
    ir.intake_status AS intake_status,
    ir.final_disposition AS final_disposition,
    ir.reported_at AS reported_at,
    ir.created_at AS created_at,
    ir.updated_at AS updated_at,
    l.public_uuid AS location_public_uuid,
    l.latitude AS location_latitude,
    l.longitude AS location_longitude,
    l.address_text AS location_address_text,
    l.place_name AS location_place_name,
    l.admin_area_id AS location_admin_area_id,
    l.source AS location_source,
    rc.channel_code AS channel_code,
    rcat.category_code AS category_code,
    EXISTS (
      SELECT 1 FROM service_cases sc WHERE sc.intake_report_id = ir.id
    ) AS has_service_case,
    EXISTS (
      SELECT 1 FROM incident_report_links irl WHERE irl.intake_report_id = ir.id
    ) AS has_incident
`;

const INTAKE_FROM = `
  FROM intake_reports ir
  INNER JOIN report_channels rc ON rc.id = ir.channel_id AND rc.is_active = TRUE
  INNER JOIN report_categories rcat ON rcat.id = ir.category_id AND rcat.is_active = TRUE
  LEFT JOIN locations l ON l.id = ir.reported_location_id
`;

/**
 * Paginated dispatcher queue view of intake reports.
 */
export async function listIntakeReportsForOperations(filters) {
  const limit = Math.min(
    Math.max(Number(filters.limit) || DEFAULT_LIMIT, 1),
    MAX_LIMIT,
  );
  const offset = Math.max(Number(filters.offset) || 0, 0);

  const filterParams = [];
  const whereSql = buildListWhere(filters, filterParams);

  const orderSql =
    filters.sort === "reported_at_asc" ? "ir.reported_at ASC" : "ir.reported_at DESC";

  const countSql = `
    SELECT COUNT(*) AS cnt
    ${INTAKE_FROM}
    ${whereSql}
  `;

  const listSql = `
    ${INTAKE_SELECT}
    ${INTAKE_FROM}
    ${whereSql}
    ORDER BY ${orderSql}
    LIMIT ?
    OFFSET ?
  `;

  const countResult = await query(countSql, filterParams);
  const listResult = await query(listSql, [...filterParams, limit, offset]);
  const countRows = countResult.rows;

  const total =
    typeof countRows[0]?.cnt === "bigint"
      ? Number(countRows[0].cnt)
      : Number(countRows[0]?.cnt || 0);
  const rows = listResult.rows;

  return {
    intake_reports: rows.map(formatIntakeRow),
    pagination: { limit, offset, total },
  };
}

function formatIntakeRow(row) {
  return {
    public_uuid: row.public_uuid,
    report_code: row.report_code,
    reporter_user_id: row.reporter_user_id != null ? String(row.reporter_user_id) : null,
    urgency_type: row.urgency_type,
    summary: row.summary,
    description: row.description,
    intake_status: row.intake_status,
    final_disposition: row.final_disposition,
    channel_code: row.channel_code,
    category_code: row.category_code,
    location: row.location_public_uuid
      ? {
          public_uuid: row.location_public_uuid,
          latitude: Number(row.location_latitude),
          longitude: Number(row.location_longitude),
          address_text: row.location_address_text,
          place_name: row.location_place_name ?? null,
          admin_area_id:
            row.location_admin_area_id != null ? Number(row.location_admin_area_id) : null,
          source: row.location_source ?? null,
        }
      : null,
    has_service_case: Boolean(row.has_service_case),
    has_incident: Boolean(row.has_incident),
    reported_at: row.reported_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

const PENDING_CLASSIFICATION_CLAUSE = "ir.intake_status IN ('received', 'under_review')";

/** Intake reports awaiting classification/triage for dispatcher dashboard counts. */
export async function countIntakeReportsPendingClassification() {
  const { rows } = await query(
    `
      SELECT COUNT(*) AS cnt
      ${INTAKE_FROM}
      WHERE ${PENDING_CLASSIFICATION_CLAUSE}
    `,
    [],
  );
  const cnt = rows[0]?.cnt;
  return typeof cnt === "bigint" ? Number(cnt) : Number(cnt ?? 0);
}

/**
 * Recent pending-classification intake rows for dispatcher overview merge.
 */
export async function listRecentIntakeReportsPendingClassification(limit) {
  const capped = Math.min(Math.max(Number(limit) || 10, 1), 50);

  const { rows } = await query(
    `
      ${INTAKE_SELECT},
      TIMESTAMPDIFF(MINUTE, ir.reported_at, CURRENT_TIMESTAMP) AS age_minutes
      ${INTAKE_FROM}
      WHERE ${PENDING_CLASSIFICATION_CLAUSE}
      ORDER BY ir.reported_at DESC
      LIMIT ?
    `,
    [capped],
  );

  return rows.map((row) => ({
    public_uuid: row.public_uuid,
    summary: row.summary,
    intake_status: row.intake_status,
    category_code: row.category_code,
    reported_at: row.reported_at,
    age_minutes: Number(row.age_minutes ?? 0),
  }));
}

export async function findIntakeReportDetailForOperations(publicUuid) {
  const { rows } = await query(
    `
      ${INTAKE_SELECT}
      ${INTAKE_FROM}
      WHERE ir.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );

  if (!rows[0]) {
    throw new BackendError(
      404,
      "INTAKE_REPORT_NOT_FOUND",
      "Intake report not found",
    );
  }

  return formatIntakeRow(rows[0]);
}
