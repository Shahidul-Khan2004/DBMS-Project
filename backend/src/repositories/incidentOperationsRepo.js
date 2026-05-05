import { randomBytes, randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import pool from "../config/db.js";
import { query } from "../config/db.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
import { updateIntakeReportStatusInTransaction } from "./intakeGatewayRepo.js";

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

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number | null} createdByUserId
 */
async function insertLocationFromPayload(conn, createdByUserId, location) {
  const normalizedLocation =
    typeof location === "string"
      ? {
          admin_area_id: null,
          latitude: 0,
          longitude: 0,
          address_text: location,
          place_name: null,
          source: "manual_entry",
        }
      : location;

  const [locationResult] = await conn.execute(
    `
      INSERT INTO locations (
        admin_area_id,
        latitude,
        longitude,
        address_text,
        place_name,
        source,
        created_by_user_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      normalizedLocation.admin_area_id ?? null,
      normalizedLocation.latitude,
      normalizedLocation.longitude,
      normalizedLocation.address_text,
      normalizedLocation.place_name ?? null,
      normalizedLocation.source ?? "dispatcher_selected",
      createdByUserId ?? null,
    ],
  );
  return locationResult.insertId;
}

const EMERGENCY_CLASSIFIABLE_STATUSES = new Set([
  "received",
  "under_review",
  "linked_to_case",
]);

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
        id,
        public_uuid,
        report_code,
        category_id,
        reported_location_id,
        urgency_type,
        summary,
        description,
        intake_status,
        reported_at
      FROM intake_reports
      WHERE public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return rows[0] || null;
}

export async function createIncidentAdminStandalone(params) {
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
      if (params.location == null || params.location === "") {
        throw new BackendError(422, "LOCATION_REQUIRED", "location is required");
      }
      categoryId = await findReportCategoryId(conn, params.categoryCode);
    }

    const locationId = intakeRow
      ? intakeRow.reported_location_id
      : await insertLocationFromPayload(conn, params.actorUserId, params.location);

    const severityLevelId = await findSeverityLevelId(conn, params.severityCode);
    const reportedStatusId = await findIncidentStatusId(conn, "reported");

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
        reportedStatusId,
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
        reportedStatusId,
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
    const reportedStatusId = await findIncidentStatusId(conn, "reported");

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
        reportedStatusId,
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
        reportedStatusId,
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
    FROM emergency_incidents ei
    INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
    INNER JOIN report_categories rcat ON rcat.id = ei.category_id
    INNER JOIN incident_severity_levels sev ON sev.id = ei.severity_level_id
    ${whereSql}
    ORDER BY ei.reported_at DESC
    LIMIT ?
    OFFSET ?
  `;

  const countResult = await query(countSql, filterParams);
  const listResult = await query(listSql, [...filterParams, limit, offset]);
  const total =
    typeof countResult.rows[0]?.cnt === "bigint"
      ? Number(countResult.rows[0].cnt)
      : Number(countResult.rows[0]?.cnt || 0);

  return {
    incidents: listResult.rows.map(mapIncidentListRow),
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
          ir.intake_status AS intake_status
        FROM incident_report_links irl
        INNER JOIN intake_reports ir ON ir.id = irl.intake_report_id
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

    return {
      incident: mapIncidentDetail(row),
      linked_intake_reports: links.map((l) => ({
        link_type: l.link_type,
        linked_at: l.linked_at,
        intake_public_uuid: l.intake_public_uuid,
        intake_report_code: l.intake_report_code,
        intake_summary: l.intake_summary,
        intake_status: l.intake_status,
      })),
      timeline_preview: timeline.map((t) => ({
        id: String(t.id),
        event_type: t.event_type,
        event_title: t.event_title,
        event_description: t.event_description,
        event_time: t.event_time,
        created_at: t.created_at,
      })),
    };
  } finally {
    conn.release();
  }
}

function mapIncidentDetail(row) {
  return {
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

    const newStatusId = await findIncidentStatusId(conn, toCode);

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
      [incidentId, newStatusId, params.actorUserId ?? null, params.note ?? null],
    );

    const updates = [];
    const values = [];

    if (toCode === "resolved") {
      updates.push("resolved_at = COALESCE(resolved_at, CURRENT_TIMESTAMP)");
    }
    if (toCode === "closed") {
      updates.push("closed_at = COALESCE(closed_at, CURRENT_TIMESTAMP)");
      updates.push("resolved_at = COALESCE(resolved_at, CURRENT_TIMESTAMP)");
    }

    if (params.outcomeCode) {
      const outcomeId = await findOutcomeId(conn, params.outcomeCode);
      updates.push("final_outcome_id = ?");
      values.push(outcomeId);
    }

    if (updates.length) {
      await conn.execute(
        `
          UPDATE emergency_incidents
          SET ${updates.join(", ")}
          WHERE id = ?
        `,
        [...values, incidentId],
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
