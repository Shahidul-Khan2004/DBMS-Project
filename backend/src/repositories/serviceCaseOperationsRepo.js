import { randomBytes, randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import pool, { query } from "../config/db.js";
import { buildDistanceSortClause } from "../lib/geoListSql.js";
import { mapRowWithOptionalDistance } from "../lib/geoSortMap.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
import { assertStatusTransitionAllowed } from "../lib/statusWorkflow.js";
import { updateIntakeReportStatusInTransaction } from "./intakeGatewayRepo.js";

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 100;

function generateCode(prefix, maxLen = 60) {
  const t = Date.now().toString(36).toUpperCase();
  const r = randomBytes(4).toString("hex").toUpperCase();
  const raw = `${prefix}-${t}-${r}`;
  return raw.length <= maxLen ? raw : raw.slice(0, maxLen);
}

async function findCaseStatusId(conn, statusCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM case_statuses
      WHERE status_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [statusCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "CASE_STATUS_NOT_FOUND", "Invalid case status code");
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
    throw new BackendError(422, "INCIDENT_STATUS_NOT_FOUND", "Invalid incident status code");
  }
  return rows[0].id;
}

async function getUserIdByPublicUuidOrThrow(conn, publicUuid, errorCode, message) {
  const [rows] = await conn.execute(
    `SELECT id FROM users WHERE public_uuid = ? LIMIT 1`,
    [publicUuid],
  );
  if (!rows[0]) {
    throw new BackendError(404, errorCode, message);
  }
  return rows[0].id;
}

async function insertAuditLog(conn, params) {
  const detailsJson =
    params.detailsJson == null ? null : JSON.stringify(params.detailsJson);
  await conn.execute(
    `
      INSERT INTO audit_logs (
        actor_user_id,
        action,
        entity_type,
        entity_id,
        related_incident_id,
        related_case_id,
        details_json,
        ip_address,
        user_agent
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      params.actorUserId ?? null,
      params.action,
      params.entityType,
      params.entityId,
      params.relatedIncidentId ?? null,
      params.relatedCaseId ?? null,
      detailsJson,
      params.ipAddress ?? null,
      params.userAgent ?? null,
    ],
  );
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

function buildServiceCaseListWhere(filters, sqlParams) {
  const clauses = [];

  if (filters.status) {
    clauses.push("cs.status_code = ?");
    sqlParams.push(filters.status);
  }
  if (filters.categoryCode) {
    clauses.push("rc.category_code = ?");
    sqlParams.push(filters.categoryCode);
  }
  if (filters.assignedToUserPublicUuid) {
    clauses.push("assignu.public_uuid = ?");
    sqlParams.push(filters.assignedToUserPublicUuid);
  }

  return clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
}

export async function listServiceCasesForOperations(filters = {}) {
  const limit = Math.min(
    Math.max(Number(filters.limit) || DEFAULT_LIST_LIMIT, 1),
    MAX_LIST_LIMIT,
  );
  const offset = Math.max(Number(filters.offset) || 0, 0);

  const filterParams = [];
  const whereSql = buildServiceCaseListWhere(
    {
      status: filters.status,
      categoryCode: filters.categoryCode,
      assignedToUserPublicUuid: filters.assignedTo,
    },
    filterParams,
  );

  const geoSort = filters.geoSort ?? null;
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance
    ? buildDistanceSortClause(
        geoSort.ref,
        "COALESCE(sc.current_location_id, ir.reported_location_id)",
      )
    : null;

  const baseFrom = `
    FROM service_cases sc
    INNER JOIN case_statuses cs ON cs.id = sc.current_status_id
    INNER JOIN report_categories rc ON rc.id = sc.category_id AND rc.is_active = TRUE
    LEFT JOIN intake_reports ir ON ir.id = sc.intake_report_id
    LEFT JOIN case_assignments ca
      ON ca.case_id = sc.id
     AND ca.assignment_status = 'active'
     AND ca.ended_at IS NULL
    LEFT JOIN users assignu ON assignu.id = ca.assigned_admin_id
  `;

  const refJoinSql = useDistance
    ? `
      LEFT JOIN locations entity_loc
        ON entity_loc.id = COALESCE(sc.current_location_id, ir.reported_location_id)
      ${distance.joinSql}
    `
    : "";

  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "sc.updated_at DESC";
  const joinParams = useDistance ? distance.joinParams : [];

  const countSql = `
    SELECT COUNT(*) AS cnt
    ${baseFrom}
    ${whereSql}
  `;

  const listSql = `
    SELECT
      sc.public_uuid AS public_uuid,
      sc.case_code AS case_code,
      sc.title AS title,
      sc.description AS description,
      sc.priority_level AS priority_level,
      sc.created_at AS created_at,
      sc.updated_at AS updated_at,
      cs.status_code AS status_code,
      rc.category_code AS category_code,
      assignu.public_uuid AS assigned_to_user_public_uuid
      ${distanceSelect}
    ${baseFrom}
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

  const mapCase = (row) => ({
    public_uuid: row.public_uuid,
    case_code: row.case_code,
    title: row.title,
    description: row.description,
    priority_level: row.priority_level,
    status_code: row.status_code,
    category_code: row.category_code,
    last_updated: row.updated_at,
    created_at: row.created_at,
    assigned_to_user_public_uuid: row.assigned_to_user_public_uuid ?? null,
  });

  return {
    service_cases: listResult.rows.map((row) =>
      mapRowWithOptionalDistance(mapCase(row), row, geoSort),
    ),
    pagination: { limit, offset, total },
  };
}

async function loadServiceCaseHeader(conn, publicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        sc.id AS id,
        sc.public_uuid AS public_uuid,
        sc.case_code AS case_code,
        sc.title AS title,
        sc.description AS description,
        sc.priority_level AS priority_level,
        sc.reporter_user_id AS reporter_user_id,
        sc.intake_report_id AS intake_report_id,
        sc.created_at AS created_at,
        sc.updated_at AS updated_at,
        cs.status_code AS status_code,
        cs.is_terminal AS is_terminal,
        rc.category_code AS category_code,
        ir.public_uuid AS intake_public_uuid,
        ir.report_code AS intake_report_code,
        l.public_uuid AS location_public_uuid,
        l.latitude AS location_latitude,
        l.longitude AS location_longitude,
        l.address_text AS location_address_text,
        l.place_name AS location_place_name,
        l.admin_area_id AS location_admin_area_id,
        l.source AS location_source
      FROM service_cases sc
      INNER JOIN case_statuses cs ON cs.id = sc.current_status_id
      INNER JOIN report_categories rc ON rc.id = sc.category_id
      INNER JOIN intake_reports ir ON ir.id = sc.intake_report_id
      LEFT JOIN locations l ON l.id = COALESCE(sc.current_location_id, ir.reported_location_id)
      WHERE sc.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return rows[0] || null;
}

function mapCaseDetailHeader(row) {
  return {
    public_uuid: row.public_uuid,
    case_code: row.case_code,
    title: row.title,
    description: row.description,
    priority_level: row.priority_level,
    status_code: row.status_code,
    category_code: row.category_code,
    intake_public_uuid: row.intake_public_uuid,
    intake_report_code: row.intake_report_code,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_updated: row.updated_at,
    location: mapLocationRow(row),
  };
}

function mapCaseMessageRow(m, { includeInternal = false } = {}) {
  const mapped = {
    id: String(m.id),
    message_type: m.message_type,
    subject: m.subject,
    body: m.body,
    created_at: m.created_at,
    sender: m.sender_public_uuid
      ? {
          public_uuid: m.sender_public_uuid,
          full_name: m.sender_full_name ?? null,
        }
      : null,
  };
  if (includeInternal) {
    mapped.is_internal = Boolean(m.is_internal);
  }
  return mapped;
}

async function fetchCaseMessages(conn, caseId, { excludeInternal = false } = {}) {
  const internalFilter = excludeInternal ? "AND cm.is_internal = FALSE" : "";
  const [messages] = await conn.execute(
    `
      SELECT
        cm.id AS id,
        cm.message_type AS message_type,
        cm.subject AS subject,
        cm.body AS body,
        cm.is_internal AS is_internal,
        cm.created_at AS created_at,
        u.public_uuid AS sender_public_uuid,
        up.full_name AS sender_full_name
      FROM case_messages cm
      LEFT JOIN users u ON u.id = cm.sender_user_id
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE cm.case_id = ?
      ${internalFilter}
      ORDER BY cm.created_at ASC, cm.id ASC
    `,
    [caseId],
  );
  return messages;
}

export async function getServiceCaseMessagesForCitizen(casePublicUuid, actorUserId) {
  const conn = await pool.getConnection();
  try {
    const header = await loadServiceCaseHeader(conn, casePublicUuid);
    if (!header) {
      throw new BackendError(404, "SERVICE_CASE_NOT_FOUND", "Service case not found");
    }
    if (Number(header.reporter_user_id) !== Number(actorUserId)) {
      throw new BackendError(403, "FORBIDDEN", "You are not the reporter for this service case");
    }

    const messages = await fetchCaseMessages(conn, header.id, { excludeInternal: true });

    return {
      public_uuid: header.public_uuid,
      case_code: header.case_code,
      messages: messages.map((m) => mapCaseMessageRow(m)),
    };
  } finally {
    conn.release();
  }
}

export async function getServiceCaseMessagesForOperations(casePublicUuid) {
  const conn = await pool.getConnection();
  try {
    const header = await loadServiceCaseHeader(conn, casePublicUuid);
    if (!header) {
      throw new BackendError(404, "SERVICE_CASE_NOT_FOUND", "Service case not found");
    }

    const messages = await fetchCaseMessages(conn, header.id);

    return {
      public_uuid: header.public_uuid,
      case_code: header.case_code,
      messages: messages.map((m) => mapCaseMessageRow(m, { includeInternal: true })),
    };
  } finally {
    conn.release();
  }
}

export async function getServiceCaseDetailForOperations(casePublicUuid) {
  const conn = await pool.getConnection();
  try {
    const header = await loadServiceCaseHeader(conn, casePublicUuid);
    if (!header) {
      throw new BackendError(404, "SERVICE_CASE_NOT_FOUND", "Service case not found");
    }

    const caseId = header.id;

    const [history] = await conn.execute(
      `
        SELECT
          csh.id AS id,
          csh.changed_at AS changed_at,
          csh.note AS note,
          cs.status_code AS status_code,
          u.public_uuid AS changed_by_public_uuid,
          up.full_name AS changed_by_full_name
        FROM case_status_history csh
        INNER JOIN case_statuses cs ON cs.id = csh.status_id
        LEFT JOIN users u ON u.id = csh.changed_by_user_id
        LEFT JOIN user_profiles up ON up.user_id = u.id
        WHERE csh.case_id = ?
        ORDER BY csh.changed_at DESC, csh.id DESC
      `,
      [caseId],
    );

    const messages = await fetchCaseMessages(conn, caseId);

    const [assignments] = await conn.execute(
      `
        SELECT
          ca.id AS id,
          ca.assignment_status AS assignment_status,
          ca.assigned_at AS assigned_at,
          ca.ended_at AS ended_at,
          ca.note AS note,
          assignee.public_uuid AS assigned_to_public_uuid,
          up.full_name AS assigned_to_full_name,
          assigner.public_uuid AS assigned_by_public_uuid
        FROM case_assignments ca
        INNER JOIN users assignee ON assignee.id = ca.assigned_admin_id
        LEFT JOIN user_profiles up ON up.user_id = assignee.id
        LEFT JOIN users assigner ON assigner.id = ca.assigned_by_user_id
        WHERE ca.case_id = ?
        ORDER BY ca.assigned_at DESC, ca.id DESC
      `,
      [caseId],
    );

    const [resolutions] = await conn.execute(
      `
        SELECT
          cr.id AS id,
          cr.resolution_type AS resolution_type,
          cr.resolution_text AS resolution_text,
          cr.recommended_facility_id AS recommended_facility_id,
          cr.resolved_at AS resolved_at,
          u.public_uuid AS resolved_by_public_uuid,
          up.full_name AS resolved_by_full_name
        FROM case_resolutions cr
        INNER JOIN users u ON u.id = cr.resolved_by_user_id
        LEFT JOIN user_profiles up ON up.user_id = u.id
        WHERE cr.case_id = ?
        LIMIT 1
      `,
      [caseId],
    );

    return {
      service_case: mapCaseDetailHeader(header),
      status_history: history.map((h) => ({
        id: String(h.id),
        status_code: h.status_code,
        changed_at: h.changed_at,
        note: h.note,
        changed_by: h.changed_by_public_uuid
          ? {
              public_uuid: h.changed_by_public_uuid,
              full_name: h.changed_by_full_name ?? null,
            }
          : null,
      })),
      messages: messages.map((m) => mapCaseMessageRow(m, { includeInternal: true })),
      assignments: assignments.map((a) => ({
        id: String(a.id),
        assignment_status: a.assignment_status,
        assigned_at: a.assigned_at,
        ended_at: a.ended_at,
        note: a.note,
        assigned_to: {
          public_uuid: a.assigned_to_public_uuid,
          full_name: a.assigned_to_full_name ?? null,
        },
        assigned_by_public_uuid: a.assigned_by_public_uuid ?? null,
      })),
      resolution: resolutions[0]
        ? {
            id: String(resolutions[0].id),
            resolution_type: resolutions[0].resolution_type,
            resolution_text: resolutions[0].resolution_text,
            recommended_facility_id:
              resolutions[0].recommended_facility_id != null
                ? Number(resolutions[0].recommended_facility_id)
                : null,
            resolved_at: resolutions[0].resolved_at,
            resolved_by: {
              public_uuid: resolutions[0].resolved_by_public_uuid,
              full_name: resolutions[0].resolved_by_full_name ?? null,
            },
          }
        : null,
    };
  } finally {
    conn.release();
  }
}

export async function listMyServiceCasesByReporterUserId(reporterUserId, options = {}) {
  const geoSort = options.geoSort ?? null;
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance
    ? buildDistanceSortClause(
        geoSort.ref,
        "COALESCE(sc.current_location_id, ir.reported_location_id)",
      )
    : null;
  const refJoinSql = useDistance
    ? `
      LEFT JOIN locations entity_loc
        ON entity_loc.id = COALESCE(sc.current_location_id, ir.reported_location_id)
      ${distance.joinSql}
    `
    : "";
  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "sc.updated_at DESC";
  const joinParams = useDistance ? distance.joinParams : [];

  const { rows } = await query(
    `
      SELECT
        sc.public_uuid AS public_uuid,
        sc.case_code AS case_code,
        sc.title AS title,
        sc.description AS description,
        sc.priority_level AS priority_level,
        sc.created_at AS created_at,
        sc.updated_at AS updated_at,
        cs.status_code AS status_code,
        rc.category_code AS category_code,
        ir.public_uuid AS intake_public_uuid,
        ir.report_code AS intake_report_code,
        l.public_uuid AS location_public_uuid,
        l.latitude AS location_latitude,
        l.longitude AS location_longitude,
        l.address_text AS location_address_text,
        l.place_name AS location_place_name,
        l.admin_area_id AS location_admin_area_id,
        l.source AS location_source
        ${distanceSelect}
      FROM service_cases sc
      INNER JOIN case_statuses cs ON cs.id = sc.current_status_id
      INNER JOIN report_categories rc ON rc.id = sc.category_id
      INNER JOIN intake_reports ir ON ir.id = sc.intake_report_id
      LEFT JOIN locations l ON l.id = COALESCE(sc.current_location_id, ir.reported_location_id)
      ${refJoinSql}
      WHERE sc.reporter_user_id = ?
      ORDER BY ${orderSql}
    `,
    [...joinParams, reporterUserId],
  );

  const mapCase = (row) => ({
    public_uuid: row.public_uuid,
    case_code: row.case_code,
    title: row.title,
    description: row.description,
    priority_level: row.priority_level,
    status_code: row.status_code,
    category_code: row.category_code,
    intake_public_uuid: row.intake_public_uuid,
    intake_report_code: row.intake_report_code,
    last_updated: row.updated_at,
    created_at: row.created_at,
    location: mapLocationRow(row),
    location_text: row.location_address_text ?? null,
  });

  return rows.map((row) => mapRowWithOptionalDistance(mapCase(row), row, geoSort));
}

/**
 * @returns {{ caseId: number, reporterUserId: number, fromStatusCode: string, isTerminal: number }}
 */
async function lockServiceCaseForStatusChange(conn, casePublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        sc.id AS id,
        sc.reporter_user_id AS reporter_user_id,
        cs.status_code AS status_code,
        cs.is_terminal AS is_terminal
      FROM service_cases sc
      INNER JOIN case_statuses cs ON cs.id = sc.current_status_id
      WHERE sc.public_uuid = ?
      LIMIT 1
      FOR UPDATE
    `,
    [casePublicUuid],
  );
  if (!rows[0]) {
    throw new BackendError(404, "SERVICE_CASE_NOT_FOUND", "Service case not found");
  }
  return {
    caseId: rows[0].id,
    reporterUserId: rows[0].reporter_user_id,
    fromStatusCode: rows[0].status_code,
    isTerminal: Boolean(rows[0].is_terminal),
  };
}

export async function patchServiceCaseStatusInTransaction(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const meta = await lockServiceCaseForStatusChange(conn, params.casePublicUuid);
    if (meta.isTerminal) {
      throw new BackendError(
        409,
        "INVALID_STATUS_TRANSITION",
        "Cannot change status of a terminal service case",
      );
    }

    const { toStatusId: newStatusId } = await assertStatusTransitionAllowed(
      conn,
      "case",
      meta.fromStatusCode,
      params.statusCode,
      { note: params.note ?? null },
    );

    await conn.execute(
      `
        INSERT INTO case_status_history (
          case_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [meta.caseId, newStatusId, params.actorUserId ?? null, params.note ?? null],
    );

    await insertAuditLog(conn, {
      actorUserId: params.actorUserId,
      action: "service_case.status_patch",
      entityType: "service_case",
      entityId: meta.caseId,
      relatedCaseId: meta.caseId,
      detailsJson: {
        from_status: meta.fromStatusCode,
        to_status: params.statusCode,
      },
      ipAddress: params.ipAddress ?? null,
      userAgent: params.userAgent ?? null,
    });

    await conn.commit();

    const detail = await getServiceCaseDetailForOperations(params.casePublicUuid);
    return {
      detail,
      fromStatusCode: meta.fromStatusCode,
      toStatusCode: params.statusCode,
      reporterUserId: meta.reporterUserId,
      caseId: meta.caseId,
      caseCode: detail.service_case.case_code,
    };
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

function normalizeMessageFields(title, description) {
  const subject = String(title ?? "").trim();
  const body = description?.trim() ? description.trim() : null;
  return { subject, body };
}

export async function postServiceCaseMessageInTransaction(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const meta = await lockServiceCaseForStatusChange(conn, params.casePublicUuid);
    if (meta.isTerminal) {
      throw new BackendError(
        409,
        "SERVICE_CASE_NOT_UPDATABLE",
        "Cannot add messages to a terminal service case",
      );
    }

    const [hdr] = await conn.execute(
      `SELECT case_code FROM service_cases WHERE id = ? LIMIT 1`,
      [meta.caseId],
    );
    const caseCode = hdr[0]?.case_code ?? null;

    const { subject, body } = normalizeMessageFields(params.title, params.description ?? "");

    const [msgResult] = await conn.execute(
      `
        INSERT INTO case_messages (
          case_id,
          sender_user_id,
          message_type,
          subject,
          body,
          is_internal
        )
        VALUES (?, ?, 'admin_reply', ?, ?, FALSE)
      `,
      [meta.caseId, params.actorUserId, subject, body],
    );

    if (meta.fromStatusCode === "under_review") {
      const { toStatusId: awaitingStatusId } = await assertStatusTransitionAllowed(
        conn,
        "case",
        meta.fromStatusCode,
        "awaiting_user_response",
      );
      await conn.execute(
        `
          INSERT INTO case_status_history (
            case_id,
            status_id,
            changed_by_user_id,
            note
          )
          VALUES (?, ?, ?, NULL)
        `,
        [meta.caseId, awaitingStatusId, params.actorUserId ?? null],
      );
      await insertAuditLog(conn, {
        actorUserId: params.actorUserId,
        action: "service_case.status_patch",
        entityType: "service_case",
        entityId: meta.caseId,
        relatedCaseId: meta.caseId,
        detailsJson: {
          from_status: meta.fromStatusCode,
          to_status: "awaiting_user_response",
          via: "dispatcher_message",
        },
        ipAddress: params.ipAddress ?? null,
        userAgent: params.userAgent ?? null,
      });
    }

    const [createdRow] = await conn.execute(
      `SELECT created_at FROM case_messages WHERE id = ? LIMIT 1`,
      [msgResult.insertId],
    );

    await insertAuditLog(conn, {
      actorUserId: params.actorUserId,
      action: "service_case.message_posted",
      entityType: "service_case",
      entityId: meta.caseId,
      relatedCaseId: meta.caseId,
      detailsJson: { case_message_id: msgResult.insertId, message_type: "admin_reply" },
      ipAddress: params.ipAddress ?? null,
      userAgent: params.userAgent ?? null,
    });

    await conn.commit();

    return {
      message: {
        id: String(msgResult.insertId),
        message_type: "admin_reply",
        subject,
        body,
        created_at: createdRow[0]?.created_at ?? null,
      },
      reporterUserId: meta.reporterUserId,
      caseId: meta.caseId,
      caseCode,
    };
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

async function getActiveCaseAssigneeUserId(conn, caseId) {
  const [rows] = await conn.execute(
    `
      SELECT assigned_admin_id
      FROM case_assignments
      WHERE case_id = ?
        AND assignment_status = 'active'
        AND ended_at IS NULL
      LIMIT 1
    `,
    [caseId],
  );
  const id = rows[0]?.assigned_admin_id;
  return id != null ? Number(id) : null;
}

export async function postCitizenServiceCaseMessageInTransaction(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const meta = await lockServiceCaseForStatusChange(conn, params.casePublicUuid);
    if (Number(meta.reporterUserId) !== Number(params.actorUserId)) {
      throw new BackendError(403, "FORBIDDEN", "You are not the reporter for this service case");
    }
    if (meta.isTerminal) {
      throw new BackendError(
        409,
        "SERVICE_CASE_NOT_UPDATABLE",
        "Cannot add messages to a terminal service case",
      );
    }

    const [hdr] = await conn.execute(
      `SELECT case_code FROM service_cases WHERE id = ? LIMIT 1`,
      [meta.caseId],
    );
    const caseCode = hdr[0]?.case_code ?? null;

    const { subject, body } = normalizeMessageFields(params.title, params.description ?? "");

    const [msgResult] = await conn.execute(
      `
        INSERT INTO case_messages (
          case_id,
          sender_user_id,
          message_type,
          subject,
          body,
          is_internal
        )
        VALUES (?, ?, 'user_message', ?, ?, FALSE)
      `,
      [meta.caseId, params.actorUserId, subject, body],
    );

    if (meta.fromStatusCode === "awaiting_user_response") {
      const { toStatusId: underReviewStatusId } = await assertStatusTransitionAllowed(
        conn,
        "case",
        meta.fromStatusCode,
        "under_review",
      );
      await conn.execute(
        `
          INSERT INTO case_status_history (
            case_id,
            status_id,
            changed_by_user_id,
            note
          )
          VALUES (?, ?, ?, NULL)
        `,
        [meta.caseId, underReviewStatusId, params.actorUserId ?? null],
      );
      await insertAuditLog(conn, {
        actorUserId: params.actorUserId,
        action: "service_case.status_patch",
        entityType: "service_case",
        entityId: meta.caseId,
        relatedCaseId: meta.caseId,
        detailsJson: {
          from_status: meta.fromStatusCode,
          to_status: "under_review",
          via: "citizen_message",
        },
        ipAddress: params.ipAddress ?? null,
        userAgent: params.userAgent ?? null,
      });
    }

    const assigneeUserId = await getActiveCaseAssigneeUserId(conn, meta.caseId);

    const [createdRow] = await conn.execute(
      `SELECT created_at FROM case_messages WHERE id = ? LIMIT 1`,
      [msgResult.insertId],
    );

    await insertAuditLog(conn, {
      actorUserId: params.actorUserId,
      action: "service_case.message_posted",
      entityType: "service_case",
      entityId: meta.caseId,
      relatedCaseId: meta.caseId,
      detailsJson: { case_message_id: msgResult.insertId, message_type: "user_message" },
      ipAddress: params.ipAddress ?? null,
      userAgent: params.userAgent ?? null,
    });

    await conn.commit();

    return {
      message: {
        id: String(msgResult.insertId),
        message_type: "user_message",
        subject,
        body,
        created_at: createdRow[0]?.created_at ?? null,
      },
      caseId: meta.caseId,
      caseCode,
      assigneeUserId,
    };
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

export async function postServiceCaseAssignmentInTransaction(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const meta = await lockServiceCaseForStatusChange(conn, params.casePublicUuid);
    if (meta.isTerminal) {
      throw new BackendError(
        409,
        "SERVICE_CASE_NOT_UPDATABLE",
        "Cannot assign a terminal service case",
      );
    }

    const assigneeUserId = await getUserIdByPublicUuidOrThrow(
      conn,
      params.assignedToUserPublicUuid,
      "ASSIGNEE_USER_NOT_FOUND",
      "Assignee user not found",
    );

    await conn.execute(
      `
        UPDATE case_assignments
        SET assignment_status = 'reassigned',
            ended_at = CURRENT_TIMESTAMP
        WHERE case_id = ?
          AND assignment_status = 'active'
          AND ended_at IS NULL
      `,
      [meta.caseId],
    );

    const [ins] = await conn.execute(
      `
        INSERT INTO case_assignments (
          case_id,
          assigned_admin_id,
          assigned_by_user_id,
          assignment_status,
          note
        )
        VALUES (?, ?, ?, 'active', ?)
      `,
      [meta.caseId, assigneeUserId, params.actorUserId ?? null, params.note ?? null],
    );

    await insertAuditLog(conn, {
      actorUserId: params.actorUserId,
      action: "service_case.assignment_posted",
      entityType: "service_case",
      entityId: meta.caseId,
      relatedCaseId: meta.caseId,
      detailsJson: { case_assignment_id: ins.insertId, assignee_user_id: assigneeUserId },
      ipAddress: params.ipAddress ?? null,
      userAgent: params.userAgent ?? null,
    });

    await conn.commit();

    return {
      assignment: {
        id: String(ins.insertId),
        assigned_to_user_public_uuid: params.assignedToUserPublicUuid,
        assignment_status: "active",
      },
      casePublicUuid: params.casePublicUuid,
    };
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

async function assertFacilityExists(conn, facilityId) {
  const [rows] = await conn.execute(
    `SELECT id FROM facilities WHERE id = ? LIMIT 1`,
    [facilityId],
  );
  if (!rows[0]) {
    throw new BackendError(422, "FACILITY_NOT_FOUND", "recommendedFacilityId is not a valid facility");
  }
}

export async function resolveServiceCaseInTransaction(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const meta = await lockServiceCaseForStatusChange(conn, params.casePublicUuid);
    if (meta.isTerminal) {
      throw new BackendError(409, "CASE_ALREADY_RESOLVED", "Service case is already in a terminal state");
    }

    const [existingRes] = await conn.execute(
      `SELECT id FROM case_resolutions WHERE case_id = ? LIMIT 1`,
      [meta.caseId],
    );
    if (existingRes[0]) {
      throw new BackendError(409, "CASE_ALREADY_RESOLVED", "Service case already has a resolution record");
    }

    if (params.recommendedFacilityId != null) {
      await assertFacilityExists(conn, params.recommendedFacilityId);
    }

    await conn.execute(
      `
        INSERT INTO case_resolutions (
          case_id,
          resolved_by_user_id,
          resolution_type,
          resolution_text,
          recommended_facility_id
        )
        VALUES (?, ?, ?, ?, ?)
      `,
      [
        meta.caseId,
        params.actorUserId,
        params.resolutionType,
        params.resolutionText,
        params.recommendedFacilityId ?? null,
      ],
    );

    const statusNote = params.statusNote ?? "Resolved via operations API";
    const { toStatusId: resolvedStatusId } = await assertStatusTransitionAllowed(
      conn,
      "case",
      meta.fromStatusCode,
      "resolved",
      { note: statusNote },
    );
    await conn.execute(
      `
        INSERT INTO case_status_history (
          case_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [meta.caseId, resolvedStatusId, params.actorUserId ?? null, statusNote],
    );

    await insertAuditLog(conn, {
      actorUserId: params.actorUserId,
      action: "service_case.resolved",
      entityType: "service_case",
      entityId: meta.caseId,
      relatedCaseId: meta.caseId,
      detailsJson: { resolution_type: params.resolutionType },
      ipAddress: params.ipAddress ?? null,
      userAgent: params.userAgent ?? null,
    });

    await conn.commit();

    const detail = await getServiceCaseDetailForOperations(params.casePublicUuid);
    return {
      detail,
      reporterUserId: meta.reporterUserId,
      caseId: meta.caseId,
      caseCode: detail.service_case.case_code,
    };
  } catch (e) {
    await conn.rollback();
    if (e?.code === "ER_DUP_ENTRY" && e.message.includes("uq_case_resolutions_case")) {
      throw new BackendError(409, "CASE_ALREADY_RESOLVED", "Service case already has a resolution record");
    }
    throw e;
  } finally {
    conn.release();
  }
}

async function loadIntakeRowForEscalation(conn, reportPublicUuid) {
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
    [reportPublicUuid],
  );
  return rows[0] || null;
}

async function loadServiceCaseByIntakeId(conn, intakeReportId) {
  const [rows] = await conn.execute(
    `
      SELECT
        sc.id AS id,
        sc.public_uuid AS public_uuid,
        sc.case_code AS case_code,
        sc.reporter_user_id AS reporter_user_id
      FROM service_cases sc
      WHERE sc.intake_report_id = ?
      LIMIT 1
    `,
    [intakeReportId],
  );
  return rows[0] || null;
}

async function resolveLatestLocationIdForEscalation(conn, intakeReportId, intakeReportedLocationId, caseRow) {
  const [hist] = await conn.execute(
    `
      SELECT location_id
      FROM intake_report_location_history
      WHERE intake_report_id = ?
      ORDER BY changed_at DESC, id DESC
      LIMIT 1
    `,
    [intakeReportId],
  );
  const fromHistory = hist[0]?.location_id ?? null;
  if (fromHistory != null) return fromHistory;
  if (intakeReportedLocationId != null) return intakeReportedLocationId;
  const [scLoc] = await conn.execute(
    `SELECT current_location_id FROM service_cases WHERE id = ? LIMIT 1`,
    [caseRow.id],
  );
  if (scLoc[0]?.current_location_id == null) {
    throw new BackendError(422, "EMERGENCY_INCIDENT_REQUIRES_LOCATION", "No location available to escalate");
  }
  return scLoc[0].current_location_id;
}

const ESCALATABLE_INTAKE_STATUSES = new Set(["linked_to_case"]);

export async function escalateIntakeServiceCaseToEmergencyInTransaction(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const intakeRow = await loadIntakeRowForEscalation(conn, params.reportPublicUuid);
    if (!intakeRow) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }

    if (!ESCALATABLE_INTAKE_STATUSES.has(intakeRow.intake_status)) {
      throw new BackendError(
        409,
        "INTAKE_NOT_ESCALATABLE",
        "Intake must be in linked_to_case status to escalate from a service case",
      );
    }

    const serviceCaseRow = await loadServiceCaseByIntakeId(conn, intakeRow.id);
    if (!serviceCaseRow) {
      throw new BackendError(409, "INTAKE_NOT_LINKED_TO_SERVICE_CASE", "No service case exists for this intake");
    }

    const [ceRow] = await conn.execute(
      `SELECT id FROM case_escalations WHERE case_id = ? LIMIT 1`,
      [serviceCaseRow.id],
    );
    if (ceRow[0]) {
      throw new BackendError(409, "CASE_ALREADY_ESCALATED", "Service case was already escalated to an incident");
    }

    const [linkDup] = await conn.execute(
      `SELECT id FROM incident_report_links WHERE intake_report_id = ? LIMIT 1`,
      [intakeRow.id],
    );
    if (linkDup[0]) {
      throw new BackendError(409, "INTAKE_ALREADY_LINKED", "Intake report is already linked to an incident");
    }

    const locationId = await resolveLatestLocationIdForEscalation(
      conn,
      intakeRow.id,
      intakeRow.reported_location_id,
      serviceCaseRow,
    );

    const severityLevelId = await findSeverityLevelId(conn, params.severityCode);
    const classifiedStatusId = await findIncidentStatusId(conn, "classified");

    const incidentPublicUuid = randomUUID();
    const incidentCode = generateCode("EMI");
    const title =
      params.incidentTitle?.trim() || intakeRow.summary || "Emergency incident";

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
        VALUES (?, ?, ?, ?, ?, ?, NULL, 'service_case_escalation', ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
      `,
      [
        incidentPublicUuid,
        incidentCode,
        intakeRow.category_id,
        severityLevelId,
        classifiedStatusId,
        locationId,
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
        `Escalated from service case ${serviceCaseRow.case_code}`,
      ],
    );

    
    const [locHistIns] = await conn.execute(
      `
        INSERT INTO incident_location_history (
          incident_id,
          location_id,
          changed_by_user_id,
          change_reason,
          is_current
        )
        VALUES (?, ?, ?, ?, FALSE)
      `,
      [
        incidentDbId,
        locationId,
        params.actorUserId ?? null,
        "Initial location from service case / intake history",
      ],
    );

    await conn.execute(
      `UPDATE incident_location_history SET is_current = TRUE WHERE id = ?`,
      [locHistIns.insertId],
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
        "Escalated from non-emergency service case",
      ],
    );

    await conn.execute(
      `
        INSERT INTO case_escalations (
          case_id,
          emergency_incident_id,
          escalated_by_user_id,
          escalation_reason
        )
        VALUES (?, ?, ?, ?)
      `,
      [serviceCaseRow.id, incidentDbId, params.actorUserId, params.escalationReason],
    );

    const caseMeta = await lockServiceCaseForStatusChange(conn, serviceCaseRow.public_uuid);
    const escalationNote = `Escalated to emergency incident ${incidentCode}`;
    const { toStatusId: escalatedStatusId } = await assertStatusTransitionAllowed(
      conn,
      "case",
      caseMeta.fromStatusCode,
      "escalated_to_emergency",
      { note: escalationNote },
    );
    await conn.execute(
      `
        INSERT INTO case_status_history (
          case_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [serviceCaseRow.id, escalatedStatusId, params.actorUserId ?? null, escalationNote],
    );

    await updateIntakeReportStatusInTransaction(
      conn,
      intakeRow.id,
      "linked_to_incident",
      params.actorUserId,
      `Escalated from service case to incident ${incidentCode}`,
    );

    await insertAuditLog(conn, {
      actorUserId: params.actorUserId,
      action: "service_case.escalated_to_emergency",
      entityType: "emergency_incident",
      entityId: incidentDbId,
      relatedIncidentId: incidentDbId,
      relatedCaseId: serviceCaseRow.id,
      detailsJson: {
        intake_public_uuid: intakeRow.public_uuid,
        service_case_public_uuid: serviceCaseRow.public_uuid,
        incident_code: incidentCode,
      },
      ipAddress: params.ipAddress ?? null,
      userAgent: params.userAgent ?? null,
    });

    await conn.commit();

    const detail = await getServiceCaseDetailForOperations(serviceCaseRow.public_uuid);
    return {
      incident: {
        public_uuid: incidentPublicUuid,
        incident_code: incidentCode,
        title,
        origin_type: "service_case_escalation",
      },
      incident_id: incidentDbId,
      service_case: detail.service_case,
      intake_public_uuid: intakeRow.public_uuid,
      reporter_user_id: serviceCaseRow.reporter_user_id,
    };
  } catch (e) {
    await conn.rollback();
    if (e?.code === "ER_DUP_ENTRY" && e.message.includes("uq_case_escalations_case")) {
      throw new BackendError(409, "CASE_ALREADY_ESCALATED", "Service case was already escalated");
    }
    throw e;
  } finally {
    conn.release();
  }
}
