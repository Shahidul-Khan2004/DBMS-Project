import BackendError from "../lib/BackendError.js";
import { query } from "../config/db.js";
import { buildDistanceSortClause } from "../lib/geoListSql.js";
import { mapRowWithOptionalDistance } from "../lib/geoSortMap.js";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

function buildListWhere(filters, params) {
  const clauses = [];

  if (filters.intake_status) {
    clauses.push("ist.status_code = ?");
    params.push(filters.intake_status);
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
    ir.summary AS summary,
    ir.description AS description,
    ist.status_code AS intake_status,
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
  INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
  INNER JOIN report_channels rc ON rc.id = ir.channel_id AND rc.is_active = TRUE
  INNER JOIN report_categories rcat ON rcat.id = ir.category_id AND rcat.is_active = TRUE
  LEFT JOIN locations l ON l.id = ir.reported_location_id
`;

const INTAKE_DETAIL_SELECT = `
  ${INTAKE_SELECT.trim()},
    ru.public_uuid AS reporter_user_public_uuid,
    rct.full_name AS reporter_contact_full_name,
    rct.phone_number AS reporter_contact_phone_number,
    rct.email AS reporter_contact_email,
    rct.is_anonymous AS reporter_is_anonymous,
    up.full_name AS reporter_profile_full_name,
    up.phone_number AS reporter_profile_phone_number,
    ec.caller_phone_number AS emergency_caller_phone_number
`;

const INTAKE_DETAIL_FROM = `
  ${INTAKE_FROM.trim()}
  LEFT JOIN reporter_contacts rct ON rct.id = ir.reporter_contact_id
  LEFT JOIN users ru ON ru.id = ir.reporter_user_id
  LEFT JOIN user_profiles up ON up.user_id = ru.id
  LEFT JOIN emergency_calls ec ON ec.intake_report_id = ir.id
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

  const geoSort = filters.geoSort ?? null;
  const useDistance = filters.sort === "distance_asc" && geoSort?.ref;
  const distance = useDistance ? buildDistanceSortClause(geoSort.ref, "entity_loc.id") : null;

  const refJoinSql = useDistance
    ? `
      INNER JOIN locations entity_loc ON entity_loc.id = ir.reported_location_id
      ${distance.joinSql}
    `
    : "";

  let orderSql =
    filters.sort === "reported_at_asc" ? "ir.reported_at ASC" : "ir.reported_at DESC";
  if (useDistance) {
    orderSql = distance.orderBySql;
  }

  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const joinParams = useDistance ? distance.joinParams : [];

  const countSql = `
    SELECT COUNT(*) AS cnt
    ${INTAKE_FROM}
    ${whereSql}
  `;

  const listSql = `
    ${INTAKE_SELECT}${distanceSelect}
    ${INTAKE_FROM}
    ${refJoinSql}
    ${whereSql}
    ORDER BY ${orderSql}
    LIMIT ?
    OFFSET ?
  `;

  const countResult = await query(countSql, filterParams);
  const listResult = await query(listSql, [...joinParams, ...filterParams, limit, offset]);
  const countRows = countResult.rows;

  const total =
    typeof countRows[0]?.cnt === "bigint"
      ? Number(countRows[0].cnt)
      : Number(countRows[0]?.cnt || 0);
  const rows = listResult.rows;

  return {
    intake_reports: rows.map((row) =>
      mapRowWithOptionalDistance(formatIntakeRow(row), row, geoSort),
    ),
    pagination: { limit, offset, total },
  };
}

function mapIntakeLocation(row) {
  if (!row.location_public_uuid) return null;
  return {
    public_uuid: row.location_public_uuid,
    latitude: Number(row.location_latitude),
    longitude: Number(row.location_longitude),
    address_text: row.location_address_text,
    place_name: row.location_place_name ?? null,
    admin_area_id:
      row.location_admin_area_id != null ? Number(row.location_admin_area_id) : null,
    source: row.location_source ?? null,
  };
}

function formatReporterFields(row) {
  const isAnonymous = Boolean(row.reporter_is_anonymous);
  if (isAnonymous) {
    return {
      user_public_uuid: null,
      full_name: null,
      phone_number: null,
      email: null,
      is_anonymous: true,
    };
  }

  const contactName = row.reporter_contact_full_name?.trim() || null;
  const profileName = row.reporter_profile_full_name?.trim() || null;
  const contactPhone = row.reporter_contact_phone_number?.trim() || null;
  const profilePhone = row.reporter_profile_phone_number?.trim() || null;

  return {
    user_public_uuid: row.reporter_user_public_uuid ?? null,
    full_name: contactName || profileName,
    phone_number: contactPhone || profilePhone,
    email: row.reporter_contact_email?.trim() || null,
    is_anonymous: false,
  };
}

function formatEmergencyCallFields(row) {
  const callerPhone = row.emergency_caller_phone_number?.trim() || null;
  if (!callerPhone) return null;
  return { caller_phone_number: callerPhone };
}

function formatIntakeRow(row) {
  return {
    public_uuid: row.public_uuid,
    report_code: row.report_code,
    reporter_user_id: row.reporter_user_id != null ? String(row.reporter_user_id) : null,
    summary: row.summary,
    description: row.description,
    intake_status: row.intake_status,
    final_disposition: row.final_disposition,
    channel_code: row.channel_code,
    category_code: row.category_code,
    location: mapIntakeLocation(row),
    has_service_case: Boolean(row.has_service_case),
    has_incident: Boolean(row.has_incident),
    reported_at: row.reported_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function formatIntakeDetailRow(row) {
  const base = formatIntakeRow(row);
  const reporter = formatReporterFields(row);
  const emergencyCall = formatEmergencyCallFields(row);
  return {
    ...base,
    reporter,
    emergency_call: emergencyCall,
  };
}

const PENDING_CLASSIFICATION_CLAUSE = "ist.status_code IN ('received', 'under_review')";

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
      ${INTAKE_DETAIL_SELECT}
      ${INTAKE_DETAIL_FROM}
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

  return formatIntakeDetailRow(rows[0]);
}