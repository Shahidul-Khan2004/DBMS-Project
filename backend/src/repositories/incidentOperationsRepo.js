import { randomBytes, randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import { assertStatusTransitionAllowed } from "../lib/statusWorkflow.js";
import pool from "../config/db.js";
import { query } from "../config/db.js";
import { buildDistanceSortClause } from "../lib/geoListSql.js";
import { mapRowWithOptionalDistance } from "../lib/geoSortMap.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
import {
  ensureIntakeUnderReviewIfReceived,
  updateIntakeReportStatusInTransaction,
} from "./intakeGatewayRepo.js";
import {
  requireAdministrativeAreaInTransaction,
  requireLocationIdByPublicUuid,
} from "../domain/locationAccess.js";
import { resolveAdminAreaIdForLocationPayload } from "../services/adminAreaFromGpsService.js";
import {
  finalizeIncidentDispatches,
  listDispatchesForIncident,
  listParticipatingAgenciesForIncident,
  releaseIncidentUnits,
} from "./dispatchOperationsRepo.js";
import { deriveAddressAndSourceForLocation } from "../services/locationAddressService.js";
import { insertLocationInTransaction } from "./locationRepo.js";

const DEFAULT_INCIDENT_LIMIT = 50;
const MAX_INCIDENT_LIMIT = 100;

function generateCode(prefix, maxLen = 60) {
  const t = Date.now().toString(36).toUpperCase();
  const r = randomBytes(4).toString("hex").toUpperCase();
  const raw = `${prefix}-${t}-${r}`;
  return raw.length <= maxLen ? raw : raw.slice(0, maxLen);
}

async function findReportCategoryId(conn, categoryCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM report_categories
      WHERE category_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [categoryCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "REPORT_CATEGORY_NOT_FOUND", "Invalid categoryCode");
  }
  return rows[0].id;
}

async function findSeverityLevelId(conn, severityCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM incident_severity_levels
      WHERE severity_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [severityCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "INCIDENT_SEVERITY_NOT_FOUND", "Invalid severityCode");
  }
  return rows[0].id;
}

async function findIncidentStatusId(conn, statusCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM incident_statuses
      WHERE status_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [statusCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "INCIDENT_STATUS_NOT_FOUND", "Invalid status code");
  }
  return rows[0].id;
}

async function findOutcomeId(conn, outcomeCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM incident_outcomes
      WHERE outcome_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [outcomeCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "INCIDENT_OUTCOME_NOT_FOUND", "Invalid outcomeCode");
  }
  return rows[0].id;
}

const EMERGENCY_CLASSIFIABLE_STATUSES = new Set([
  "received",
  "under_review",
  "linked_to_case",
]);

const TERMINAL_INCIDENT_STATUSES = new Set(["resolved", "closed", "cancelled"]);

function assertIntakeEligibleForIncident(intakeRow) {
  if (!EMERGENCY_CLASSIFIABLE_STATUSES.has(intakeRow.intake_status)) {
    throw new BackendError(
      409,
      "INTAKE_NOT_PROMOTABLE",
      "Intake report cannot become an incident in its current status",
    );
  }
}

async function loadIntakeRowByPublicUuid(conn, publicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        ir.id AS id,
        ir.public_uuid AS public_uuid,
        ir.report_code AS report_code,
        ir.category_id AS category_id,
        ir.reported_location_id AS reported_location_id,
        ir.summary AS summary,
        ir.description AS description,
        ist.status_code AS intake_status,
        ir.reported_at AS reported_at
      FROM intake_reports ir
      INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
      WHERE ir.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return rows[0] || null;
}

async function loadIncidentByPublicUuid(conn, publicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        ei.id AS id,
        ei.public_uuid AS public_uuid,
        ei.incident_code AS incident_code,
        ist.status_code AS status_code
      FROM emergency_incidents ei
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return rows[0] || null;
}

export async function createIncidentAdminStandalone(params) {
  let gpsResolvedAdminAreaId = null;
  if (
    params.location &&
    !params.locationId &&
    !params.intakeReportPublicUuid &&
    params.location.admin_area_id == null
  ) {
    const r = await resolveAdminAreaIdForLocationPayload({
      explicitAdminAreaId: null,
      latitude: params.location.latitude,
      longitude: params.location.longitude,
      pool,
    });
    gpsResolvedAdminAreaId = r.adminAreaId;
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    let intakeRow = null;
    if (params.intakeReportPublicUuid) {
      intakeRow = await loadIntakeRowByPublicUuid(conn, params.intakeReportPublicUuid);
      if (!intakeRow) {
        throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
      }
      assertIntakeEligibleForIncident(intakeRow);
      if (intakeRow.reported_location_id == null) {
        throw new BackendError(
          422,
          "EMERGENCY_INCIDENT_REQUIRES_LOCATION",
          "Intake report has no location; cannot link to emergency incident",
        );
      }
      const [linkDup] = await conn.execute(
        `
          SELECT id FROM incident_report_links WHERE intake_report_id = ? LIMIT 1
        `,
        [intakeRow.id],
      );
      if (linkDup[0]) {
        throw new BackendError(
          409,
          "INTAKE_ALREADY_LINKED",
          "Intake report is already linked to an incident",
        );
      }
    }

    let categoryId;
    if (intakeRow) {
      categoryId = intakeRow.category_id;
    } else {
      if (!params.categoryCode) {
        throw new BackendError(422, "CATEGORY_REQUIRED", "categoryCode is required");
      }
      if (params.location == null && params.locationId == null) {
        throw new BackendError(422, "LOCATION_REQUIRED", "location or locationId is required");
      }
      categoryId = await findReportCategoryId(conn, params.categoryCode);
    }

    let locationId = intakeRow ? intakeRow.reported_location_id : null;
    if (!intakeRow) {
      if (params.locationId) {
        locationId = await requireLocationIdByPublicUuid(conn, params.locationId);
      } else if (params.location) {
        const normalized = {
          ...params.location,
          source: params.location.source ?? "dispatcher_selected",
        };
        const derivedAddress = await deriveAddressAndSourceForLocation({
          latitude: normalized.latitude,
          longitude: normalized.longitude,
          addressText: normalized.address_text ?? null,
          source: normalized.source ?? null,
        });
        const adminAreaIdToUse = normalized.admin_area_id ?? gpsResolvedAdminAreaId ?? null;
        if (adminAreaIdToUse != null) {
          await requireAdministrativeAreaInTransaction(conn, adminAreaIdToUse);
        }
        const inserted = await insertLocationInTransaction(conn, {
          admin_area_id: adminAreaIdToUse,
          latitude: normalized.latitude,
          longitude: normalized.longitude,
          address_text: derivedAddress.addressText,
          place_name: normalized.place_name ?? null,
          source: derivedAddress.source ?? normalized.source,
          created_by_user_id: params.actorUserId ?? null,
        });
        locationId = Number(inserted.id);
      }
    }

    const severityLevelId = await findSeverityLevelId(conn, params.severityCode);
    const classifiedStatusId = await findIncidentStatusId(conn, "classified");

    const incidentPublicUuid = randomUUID();
    const incidentCode = generateCode("EMI");

    const title = params.title?.trim() || intakeRow?.summary;
    if (!title || !String(title).trim()) {
      throw new BackendError(422, "INCIDENT_TITLE_REQUIRED", "title is required");
    }

    const [incidentResult] = await conn.execute(
      `
        INSERT INTO emergency_incidents (
          public_uuid,
          incident_code,
          category_id,
          severity_level_id,
          current_status_id,
          current_location_id,
          final_outcome_id,
          origin_type,
          title,
          description,
          created_by_user_id,
          reported_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, 'admin_created', ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
      `,
      [
        incidentPublicUuid,
        incidentCode,
        categoryId,
        severityLevelId,
        classifiedStatusId,
        locationId,
        title.trim(),
        params.description ?? intakeRow?.description ?? null,
        params.actorUserId,
        toMySqlDateTimeOrNull(params.reportedAt),
      ],
    );

    const incidentDbId = incidentResult.insertId;

    await conn.execute(
      `
        INSERT INTO incident_status_history (
          incident_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [
        incidentDbId,
        classifiedStatusId,
        params.actorUserId ?? null,
        intakeRow
          ? `Created from linked intake ${intakeRow.public_uuid}`
          : "Created by dispatcher (admin_created)",
      ],
    );

    if (intakeRow) {
      await conn.execute(
        `
          INSERT INTO incident_report_links (
            incident_id,
            intake_report_id,
            link_type,
            linked_by_user_id,
            note
          )
          VALUES (?, ?, 'primary_report', ?, ?)
        `,
        [
          incidentDbId,
          intakeRow.id,
          params.actorUserId ?? null,
          `Linked during standalone incident creation`,
        ],
      );

      await ensureIntakeUnderReviewIfReceived(
        conn,
        intakeRow.id,
        intakeRow.intake_status,
        params.actorUserId,
        "Under review before incident linkage",
      );

      await updateIntakeReportStatusInTransaction(
        conn,
        intakeRow.id,
        "linked_to_incident",
        params.actorUserId,
        `Linked to incident ${incidentCode}`,
      );
    }

    const detail = await loadIncidentDetailRow(conn, incidentPublicUuid);
    await conn.commit();
    return mapIncidentDetail(detail);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function promoteIntakeReportToEmergencyIncident(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const intakeRow = await loadIntakeRowByPublicUuid(conn, params.intakeReportPublicUuid);
    if (!intakeRow) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }
    if (intakeRow.reported_location_id == null) {
      throw new BackendError(
        422,
        "EMERGENCY_INCIDENT_REQUIRES_LOCATION",
        "Emergency incidents require a location on the intake report",
      );
    }

    assertIntakeEligibleForIncident(intakeRow);

    const [linkDup] = await conn.execute(
      `
        SELECT id FROM incident_report_links WHERE intake_report_id = ? LIMIT 1
      `,
      [intakeRow.id],
    );
    if (linkDup[0]) {
      throw new BackendError(
        409,
        "INTAKE_ALREADY_LINKED",
        "Intake report is already linked to an emergency path",
      );
    }

    const severityLevelId = await findSeverityLevelId(conn, params.severityCode);
    const classifiedStatusId = await findIncidentStatusId(conn, "classified");

    const incidentPublicUuid = randomUUID();
    const incidentCode = generateCode("EMI");

    const title =
      params.incidentTitle?.trim() ||
      intakeRow.summary ||
      "Emergency incident";

    const [incidentResult] = await conn.execute(
      `
        INSERT INTO emergency_incidents (
          public_uuid,
          incident_code,
          category_id,
          severity_level_id,
          current_status_id,
          current_location_id,
          final_outcome_id,
          origin_type,
          title,
          description,
          created_by_user_id,
          reported_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, 'admin_created', ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
      `,
      [
        incidentPublicUuid,
        incidentCode,
        intakeRow.category_id,
        severityLevelId,
        classifiedStatusId,
        intakeRow.reported_location_id,
        title,
        params.incidentDescription ?? intakeRow.description ?? null,
        params.actorUserId,
        toMySqlDateTimeOrNull(params.reportedAt ?? intakeRow.reported_at),
      ],
    );

    const incidentDbId = incidentResult.insertId;

    await conn.execute(
      `
        INSERT INTO incident_status_history (
          incident_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [
        incidentDbId,
        classifiedStatusId,
        params.actorUserId ?? null,
        `Promoted from intake ${intakeRow.public_uuid} (operations)`,
      ],
    );

    await conn.execute(
      `
        INSERT INTO incident_report_links (
          incident_id,
          intake_report_id,
          link_type,
          linked_by_user_id,
          note
        )
        VALUES (?, ?, 'primary_report', ?, ?)
      `,
      [
        incidentDbId,
        intakeRow.id,
        params.actorUserId ?? null,
        "Promoted on emergency path (no call record)",
      ],
    );

    await ensureIntakeUnderReviewIfReceived(
      conn,
      intakeRow.id,
      intakeRow.intake_status,
      params.actorUserId,
      "Under review before incident promotion",
    );

    await updateIntakeReportStatusInTransaction(
      conn,
      intakeRow.id,
      "linked_to_incident",
      params.actorUserId,
      `Linked to incident ${incidentCode}`,
    );

    const detail = await loadIncidentDetailRow(conn, incidentPublicUuid);
    await conn.commit();
    return mapIncidentDetail(detail);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function linkIntakeReportToIncident(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const incident = await loadIncidentByPublicUuid(conn, params.incidentPublicUuid);
    if (!incident) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }
    if (TERMINAL_INCIDENT_STATUSES.has(incident.status_code)) {
      throw new BackendError(
        409,
        "INCIDENT_NOT_LINKABLE",
        "Cannot link intake report to a terminal incident",
      );
    }

    const intakeRow = await loadIntakeRowByPublicUuid(conn, params.intakeReportPublicUuid);
    if (!intakeRow) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }
    assertIntakeEligibleForIncident(intakeRow);
    if (intakeRow.reported_location_id == null) {
      throw new BackendError(
        422,
        "EMERGENCY_INCIDENT_REQUIRES_LOCATION",
        "Intake report has no location; cannot link to incident",
      );
    }

    const [linkDup] = await conn.execute(
      `
        SELECT id FROM incident_report_links WHERE intake_report_id = ? LIMIT 1
      `,
      [intakeRow.id],
    );
    if (linkDup[0]) {
      throw new BackendError(
        409,
        "INTAKE_ALREADY_LINKED",
        "Intake report is already linked to an incident",
      );
    }

    const [linkResult] = await conn.execute(
      `
        INSERT INTO incident_report_links (
          incident_id,
          intake_report_id,
          link_type,
          linked_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?, ?)
      `,
      [
        incident.id,
        intakeRow.id,
        params.linkType ?? "supporting_report",
        params.actorUserId ?? null,
        params.note ?? null,
      ],
    );

    await ensureIntakeUnderReviewIfReceived(
      conn,
      intakeRow.id,
      intakeRow.intake_status,
      params.actorUserId,
      "Under review before incident linkage",
    );

    await updateIntakeReportStatusInTransaction(
      conn,
      intakeRow.id,
      "linked_to_incident",
      params.actorUserId,
      `Linked to incident ${incident.incident_code}`,
    );

    const [rows] = await conn.execute(
      `
        SELECT
          irl.id,
          irl.link_type,
          irl.linked_at,
          irl.note,
          ei.public_uuid AS incident_public_uuid,
          ei.incident_code AS incident_code,
          ir.public_uuid AS intake_report_public_uuid,
          ir.report_code AS intake_report_code
        FROM incident_report_links irl
        INNER JOIN emergency_incidents ei ON ei.id = irl.incident_id
        INNER JOIN intake_reports ir ON ir.id = irl.intake_report_id
        WHERE irl.id = ?
        LIMIT 1
      `,
      [linkResult.insertId],
    );

    await conn.commit();
    return rows[0];
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

function buildIncidentListWhere(filters, params) {
  const clauses = [];

  if (filters.status_code) {
    clauses.push("ist.status_code = ?");
    params.push(filters.status_code);
  }
  if (filters.reported_after) {
    clauses.push("ei.reported_at >= ?");
    params.push(filters.reported_after);
  }
  if (filters.reported_before) {
    clauses.push("ei.reported_at <= ?");
    params.push(filters.reported_before);
  }

  return clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
}

export async function listIncidentsForOperations(filters) {
  const limit = Math.min(
    Math.max(Number(filters.limit) || DEFAULT_INCIDENT_LIMIT, 1),
    MAX_INCIDENT_LIMIT,
  );
  const offset = Math.max(Number(filters.offset) || 0, 0);

  const filterParams = [];
  const whereSql = buildIncidentListWhere(filters, filterParams);
  const geoSort = filters.geoSort ?? null;
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance ? buildDistanceSortClause(geoSort.ref, "entity_loc.id") : null;

  const refJoinSql = useDistance
    ? `
      LEFT JOIN locations entity_loc ON entity_loc.id = ei.current_location_id
      ${distance.joinSql}
    `
    : "";
  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "ei.reported_at DESC";
  const joinParams = useDistance ? distance.joinParams : [];

  const countSql = `
    SELECT COUNT(*) AS cnt
    FROM emergency_incidents ei
    INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
    ${whereSql}
  `;

  const listSql = `
    SELECT
      ei.public_uuid AS public_uuid,
      ei.incident_code AS incident_code,
      ei.title AS title,
      ei.description AS description,
      ei.origin_type AS origin_type,
      ei.reported_at AS reported_at,
      ei.resolved_at AS resolved_at,
      ei.closed_at AS closed_at,
      ei.created_at AS created_at,
      ei.updated_at AS updated_at,
      ist.status_code AS status_code,
      rcat.category_code AS category_code,
      sev.severity_code AS severity_code
      ${distanceSelect}
    FROM emergency_incidents ei
    INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
    INNER JOIN report_categories rcat ON rcat.id = ei.category_id
    INNER JOIN incident_severity_levels sev ON sev.id = ei.severity_level_id
    ${refJoinSql}
    ${whereSql}
    ORDER BY ${orderSql}
    LIMIT ?
    OFFSET ?
  `;

  const countResult = await query(countSql, filterParams);
  const listResult = await query(listSql, [...joinParams, ...filterParams, limit, offset]);
  const total =
    typeof countResult.rows[0]?.cnt === "bigint"
      ? Number(countResult.rows[0].cnt)
      : Number(countResult.rows[0]?.cnt || 0);

  return {
    incidents: listResult.rows.map((row) =>
      mapRowWithOptionalDistance(mapIncidentListRow(row), row, geoSort),
    ),
    pagination: { limit, offset, total },
  };
}

function mapIncidentListRow(row) {
  return {
    public_uuid: row.public_uuid,
    incident_code: row.incident_code,
    title: row.title,
    description: row.description,
    origin_type: row.origin_type,
    status_code: row.status_code,
    category_code: row.category_code,
    severity_code: row.severity_code,
    reported_at: row.reported_at,
    resolved_at: row.resolved_at,
    closed_at: row.closed_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function mapLocationRow(row) {
  if (row?.location_public_uuid == null) return null;
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

function mapMyIncidentRow(row) {
  return {
    public_uuid: row.public_uuid,
    incident_code: row.incident_code,
    title: row.title,
    description: row.description,
    origin_type: row.origin_type,
    status_code: row.status_code,
    category_code: row.category_code,
    severity_code: row.severity_code,
    intake_public_uuid: row.intake_public_uuid,
    intake_report_code: row.intake_report_code,
    reported_at: row.reported_at,
    resolved_at: row.resolved_at,
    closed_at: row.closed_at,
    created_at: row.created_at,
    last_updated: row.updated_at,
    location: mapLocationRow(row),
    location_text: row.location_address_text ?? null,
  };
}

/**
 * Lists emergency incidents linked to intake reports owned by the reporter.
 * Prefers primary_report link when multiple reports from the same reporter exist.
 */
export async function listMyIncidentsByReporterUserId(reporterUserId, options = {}) {
  const geoSort = options.geoSort ?? null;
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance ? buildDistanceSortClause(geoSort.ref, "entity_loc.id") : null;
  const refJoinSql = useDistance
    ? `
      LEFT JOIN locations entity_loc
        ON entity_loc.id = COALESCE(ei.current_location_id, preferred.reported_location_id)
      ${distance.joinSql}
    `
    : "";
  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "ei.updated_at DESC";
  const joinParams = useDistance ? distance.joinParams : [];

  const { rows } = await query(
    `
      SELECT
        ei.public_uuid AS public_uuid,
        ei.incident_code AS incident_code,
        ei.title AS title,
        ei.description AS description,
        ei.origin_type AS origin_type,
        ei.reported_at AS reported_at,
        ei.resolved_at AS resolved_at,
        ei.closed_at AS closed_at,
        ei.created_at AS created_at,
        ei.updated_at AS updated_at,
        ist.status_code AS status_code,
        rcat.category_code AS category_code,
        sev.severity_code AS severity_code,
        preferred.intake_public_uuid AS intake_public_uuid,
        preferred.intake_report_code AS intake_report_code,
        l.public_uuid AS location_public_uuid,
        l.latitude AS location_latitude,
        l.longitude AS location_longitude,
        l.address_text AS location_address_text,
        l.place_name AS location_place_name,
        l.admin_area_id AS location_admin_area_id,
        l.source AS location_source
        ${distanceSelect}
      FROM emergency_incidents ei
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      INNER JOIN report_categories rcat ON rcat.id = ei.category_id
      INNER JOIN incident_severity_levels sev ON sev.id = ei.severity_level_id
      INNER JOIN (
        SELECT
          irl.incident_id,
          ir.public_uuid AS intake_public_uuid,
          ir.report_code AS intake_report_code,
          ir.reported_location_id,
          ROW_NUMBER() OVER (
            PARTITION BY irl.incident_id
            ORDER BY (irl.link_type = 'primary_report') DESC, irl.linked_at ASC
          ) AS rn
        FROM incident_report_links irl
        INNER JOIN intake_reports ir ON ir.id = irl.intake_report_id
        WHERE ir.reporter_user_id = ?
      ) preferred ON preferred.incident_id = ei.id AND preferred.rn = 1
      LEFT JOIN locations l
        ON l.id = COALESCE(ei.current_location_id, preferred.reported_location_id)
      ${refJoinSql}
      ORDER BY ${orderSql}
    `,
    useDistance ? [reporterUserId, ...joinParams] : [reporterUserId],
  );

  return rows.map((row) => mapRowWithOptionalDistance(mapMyIncidentRow(row), row, geoSort));
}

const ACTIVE_INCIDENT_BASE = `
  FROM emergency_incidents ei
  INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
  INNER JOIN report_categories rcat ON rcat.id = ei.category_id AND rcat.is_active = TRUE
  INNER JOIN incident_severity_levels sev ON sev.id = ei.severity_level_id
`;

/** Incidents whose current incident_status is non-terminal (dispatcher overview count). */
export async function countActiveIncidentsForOperations() {
  const { rows } = await query(
    `
      SELECT COUNT(*) AS cnt
      ${ACTIVE_INCIDENT_BASE}
      WHERE ist.is_terminal = FALSE
    `,
    [],
  );
  const cnt = rows[0]?.cnt;
  return typeof cnt === "bigint" ? Number(cnt) : Number(cnt ?? 0);
}

/**
 * Recent active incidents for dispatcher overview merge (age from reported_at).
 */
export async function listRecentActiveIncidentsForOverview(limit) {
  const capped = Math.min(Math.max(Number(limit) || 10, 1), 50);

  const { rows } = await query(
    `
      SELECT
        ei.public_uuid AS public_uuid,
        ei.title AS title,
        ist.status_code AS status_code,
        rcat.category_code AS category_code,
        ei.reported_at AS reported_at,
        TIMESTAMPDIFF(MINUTE, ei.reported_at, CURRENT_TIMESTAMP) AS age_minutes
      ${ACTIVE_INCIDENT_BASE}
      WHERE ist.is_terminal = FALSE
      ORDER BY ei.reported_at DESC
      LIMIT ?
    `,
    [capped],
  );

  return rows.map((row) => ({
    public_uuid: row.public_uuid,
    title: row.title,
    status_code: row.status_code,
    category_code: row.category_code,
    reported_at: row.reported_at,
    age_minutes: Number(row.age_minutes ?? 0),
  }));
}

async function loadIncidentDetailRow(conn, publicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        ei.id AS id,
        ei.public_uuid AS public_uuid,
        ei.incident_code AS incident_code,
        ei.title AS title,
        ei.description AS description,
        ei.origin_type AS origin_type,
        ei.reported_at AS reported_at,
        ei.resolved_at AS resolved_at,
        ei.closed_at AS closed_at,
        ei.created_at AS created_at,
        ei.updated_at AS updated_at,
        ei.final_outcome_id AS final_outcome_id,
        ist.status_code AS status_code,
        rcat.category_code AS category_code,
        sev.severity_code AS severity_code,
        io.outcome_code AS outcome_code
      FROM emergency_incidents ei
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      INNER JOIN report_categories rcat ON rcat.id = ei.category_id
      INNER JOIN incident_severity_levels sev ON sev.id = ei.severity_level_id
      LEFT JOIN incident_outcomes io ON io.id = ei.final_outcome_id
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return rows[0] || null;
}

export async function getIncidentDetailForOperations(publicUuid) {
  const conn = await pool.getConnection();
  try {
    const row = await loadIncidentDetailRow(conn, publicUuid);
    if (!row) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }

    const [links] = await conn.execute(
      `
        SELECT
          irl.link_type AS link_type,
          irl.linked_at AS linked_at,
          ir.public_uuid AS intake_public_uuid,
          ir.report_code AS intake_report_code,
          ir.summary AS intake_summary,
          ints.status_code AS intake_status,
          l.public_uuid AS location_public_uuid,
          l.latitude AS location_latitude,
          l.longitude AS location_longitude,
          l.address_text AS location_address_text,
          l.place_name AS location_place_name,
          l.admin_area_id AS location_admin_area_id,
          l.source AS location_source
        FROM incident_report_links irl
        INNER JOIN intake_reports ir ON ir.id = irl.intake_report_id
        INNER JOIN intake_statuses ints ON ints.id = ir.current_status_id
        LEFT JOIN locations l ON l.id = ir.reported_location_id
        WHERE irl.incident_id = ?
        ORDER BY irl.linked_at ASC
      `,
      [row.id],
    );

    const timelineLimit = 50;
    const [timeline] = await conn.execute(
      `
        SELECT
          id,
          event_type AS event_type,
          event_title AS event_title,
          event_description AS event_description,
          event_time AS event_time,
          created_at AS created_at
        FROM incident_timeline_events
        WHERE incident_id = ?
        ORDER BY event_time DESC, id DESC
        LIMIT ${timelineLimit}
      `,
      [row.id],
    );

    const participating_agencies = await listParticipatingAgenciesForIncident(
      conn,
      row.id,
    );
    const dispatches = await listDispatchesForIncident(conn, row.id);

    return {
      incident: mapIncidentDetail(row),
      linked_intake_reports: links.map((l) => ({
        link_type: l.link_type,
        linked_at: l.linked_at,
        intake_public_uuid: l.intake_public_uuid,
        intake_report_code: l.intake_report_code,
        intake_summary: l.intake_summary,
        intake_status: l.intake_status,
        location: l.location_public_uuid
          ? {
              public_uuid: l.location_public_uuid,
              latitude: Number(l.location_latitude),
              longitude: Number(l.location_longitude),
              address_text: l.location_address_text,
              place_name: l.location_place_name ?? null,
              admin_area_id:
                l.location_admin_area_id != null ? Number(l.location_admin_area_id) : null,
              source: l.location_source ?? null,
            }
          : null,
      })),
      timeline_preview: timeline.map(mapTimelineEventRow),
      participating_agencies,
      dispatches,
    };
  } finally {
    conn.release();
  }
}

function mapTimelineEventRow(row) {
  return {
    id: String(row.id),
    event_type: row.event_type,
    event_title: row.event_title,
    event_description: row.event_description,
    event_time: row.event_time,
    created_at: row.created_at,
  };
}

export async function listIncidentOperatorNotes(incidentPublicUuid, { limit = 20, offset = 0 } = {}) {
  const safeLimit = Math.min(Math.max(limit, 1), 100);
  const safeOffset = Math.max(offset, 0);

  const [incidentRows] = await pool.execute(
    `
      SELECT id FROM emergency_incidents WHERE public_uuid = ? LIMIT 1
    `,
    [incidentPublicUuid],
  );
  if (!incidentRows[0]) {
    throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  }

  const [rows] = await pool.execute(
    `
      SELECT
        id,
        event_type AS event_type,
        event_title AS event_title,
        event_description AS event_description,
        event_time AS event_time,
        created_at AS created_at
      FROM incident_timeline_events
      WHERE incident_id = ?
        AND event_type = 'operator_note'
      ORDER BY event_time DESC, id DESC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [incidentRows[0].id],
  );

  return {
    incident_public_uuid: incidentPublicUuid,
    limit: safeLimit,
    offset: safeOffset,
    notes: rows.map(mapTimelineEventRow),
  };
}

function mapIncidentDetail(row) {
  return {
    id: row.id,                          // internal DB id — needed for notification entityId
    public_uuid: row.public_uuid,
    incident_code: row.incident_code,
    title: row.title,
    description: row.description,
    origin_type: row.origin_type,
    status_code: row.status_code,
    category_code: row.category_code,
    severity_code: row.severity_code,
    outcome_code: row.outcome_code ?? null,
    reported_at: row.reported_at,
    resolved_at: row.resolved_at,
    closed_at: row.closed_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

/**
 * Returns the distinct reporter_user_id values for all intake reports linked
 * to a given incident. Returns an empty array when the incident was admin-created
 * with no linked intake, or when no reporter is attached.
 *
 * Used by notification hooks that need to know who to notify about incident changes.
 *
 * @param {string} incidentPublicUuid
 * @returns {Promise<number[]>}
 */
export async function getIncidentReporterUserIds(incidentPublicUuid) {
  const result = await query(
    `
      SELECT DISTINCT ir.reporter_user_id
      FROM emergency_incidents ei
      INNER JOIN incident_report_links irl ON irl.incident_id = ei.id
      INNER JOIN intake_reports ir ON ir.id = irl.intake_report_id
      WHERE ei.public_uuid = ?
        AND ir.reporter_user_id IS NOT NULL
    `,
    [incidentPublicUuid],
  );
  return result.rows.map((r) => r.reporter_user_id);
}

export async function applyIncidentStatusChange(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute(
      `
        SELECT
          ei.id AS id,
          ist.status_code AS current_status_code
        FROM emergency_incidents ei
        INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
        WHERE ei.public_uuid = ?
        LIMIT 1
      `,
      [params.incidentPublicUuid],
    );

    if (!rows[0]) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }

    const incidentId = rows[0].id;
    const fromCode = rows[0].current_status_code;
    const toCode = params.statusCode;

    let outcomeId = null;
    if (params.outcomeCode) {
      outcomeId = await findOutcomeId(conn, params.outcomeCode);
    }

    const { toStatusId: newStatusId } = await assertStatusTransitionAllowed(
      conn,
      "incident",
      fromCode,
      toCode,
      { note: params.note ?? null, outcomeId },
    );

    await conn.execute(
      `
        INSERT INTO incident_status_history (
          incident_id,
          status_id,
          outcome_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?, ?)
      `,
      [incidentId, newStatusId, outcomeId, params.actorUserId ?? null, params.note ?? null],
    );

    if (TERMINAL_INCIDENT_STATUSES.has(toCode)) {
      await finalizeIncidentDispatches(conn, incidentId, toCode, params.actorUserId);
      await releaseIncidentUnits(
        conn,
        incidentId,
        params.actorUserId,
        `Incident ${toCode}`,
      );
    }

    await conn.commit();

    const row = await loadIncidentDetailRow(conn, params.incidentPublicUuid);
    return mapIncidentDetail(row);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function insertIncidentOperatorNote(params) {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.execute(
      `
        SELECT id FROM emergency_incidents WHERE public_uuid = ? LIMIT 1
      `,
      [params.incidentPublicUuid],
    );
    if (!rows[0]) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }
    const incidentId = rows[0].id;

    const [result] = await conn.execute(
      `
        INSERT INTO incident_timeline_events (
          incident_id,
          event_type,
          event_title,
          event_description,
          created_by_user_id,
          event_time
        )
        VALUES (?, 'operator_note', ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
      `,
      [
        incidentId,
        params.title.trim(),
        params.description ?? null,
        params.actorUserId ?? null,
        toMySqlDateTimeOrNull(params.eventTime),
      ],
    );

    return {
      id: String(result.insertId),
      event_type: "operator_note",
      event_title: params.title.trim(),
      event_description: params.description ?? null,
    };
  } finally {
    conn.release();
  }
}