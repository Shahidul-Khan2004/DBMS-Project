import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import { insertAuditLog } from "../lib/auditLog.js";
import { generateCode } from "../lib/generateCode.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
import { assertStatusTransitionAllowed } from "../lib/statusWorkflow.js";
import pool from "../config/db.js";
import { query } from "../config/db.js";
import { listUpazilaIdsUnderDistrict } from "./administrativeAreaSearchRepo.js";

const DEFAULT_DISASTER_LIMIT = 50;
const MAX_DISASTER_LIMIT = 100;

const TERMINAL_INCIDENT_STATUSES = new Set(["resolved", "closed", "cancelled"]);
const DISASTER_LINK_BLOCKED_STATUSES = new Set(["resolved", "closed", "cancelled"]);
const AFFECTED_AREA_ALLOWED_STATUSES = new Set(["monitoring", "declared"]);
const OPEN_RELIEF_REQUEST_STATUSES = new Set([
  "submitted",
  "approved",
  "partially_fulfilled",
]);

const VALID_SEVERITY_LEVELS = new Set([
  "low",
  "medium",
  "high",
  "critical",
  "national",
]);

const SHELTER_CAPABILITY = "temporary_shelter";
const HUB_CAPABILITY = "relief_distribution_hub";

function auditFields(auditMeta = {}) {
  return {
    ipAddress: auditMeta.ipAddress ?? null,
    userAgent: auditMeta.userAgent ?? null,
  };
}

async function writeAudit(conn, params) {
  await insertAuditLog(conn, {
    actorUserId: params.actorUserId ?? null,
    action: params.action,
    entityType: params.entityType,
    entityId: params.entityId,
    relatedDisasterEventId: params.relatedDisasterEventId ?? null,
    detailsJson: params.detailsJson ?? null,
    ...auditFields(params.auditMeta),
  });
}

async function findDisasterEventTypeId(conn, typeCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM disaster_event_types
      WHERE type_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [typeCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "DISASTER_TYPE_NOT_FOUND", "Invalid eventTypeCode");
  }
  return rows[0].id;
}

async function loadDisasterRow(conn, publicUuid, { forUpdate = false } = {}) {
  const lock = forUpdate ? " FOR UPDATE" : "";
  const [rows] = await conn.execute(
    `
      SELECT
        de.id AS id,
        de.public_uuid AS public_uuid,
        de.event_code AS event_code,
        de.title AS title,
        de.description AS description,
        de.public_guidance AS public_guidance,
        de.severity_level AS severity_level,
        de.started_at AS started_at,
        de.ended_at AS ended_at,
        de.created_at AS created_at,
        de.updated_at AS updated_at,
        des.status_code AS status_code,
        des.is_terminal AS is_terminal,
        det.type_code AS event_type_code,
        det.name AS event_type_name
      FROM disaster_events de
      INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
      INNER JOIN disaster_event_types det ON det.id = de.event_type_id
      WHERE de.public_uuid = ?
      LIMIT 1${lock}
    `,
    [publicUuid],
  );
  return rows[0] || null;
}

async function requireDisaster(conn, publicUuid, options) {
  const row = await loadDisasterRow(conn, publicUuid, options);
  if (!row) {
    throw new BackendError(404, "DISASTER_NOT_FOUND", "Disaster event not found");
  }
  return row;
}

async function loadAgencyByPublicUuid(conn, agencyPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT id, public_uuid, name, is_active
      FROM agencies
      WHERE public_uuid = ?
      LIMIT 1
    `,
    [agencyPublicUuid],
  );
  return rows[0] || null;
}

async function loadFacilityByPublicUuid(conn, facilityPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT id, public_uuid, name, facility_code, is_active, location_id
      FROM facilities
      WHERE public_uuid = ?
      LIMIT 1
    `,
    [facilityPublicUuid],
  );
  return rows[0] || null;
}

async function assertUpazilaAdminArea(conn, adminAreaId) {
  const [rows] = await conn.execute(
    `
      SELECT id, area_type, name, parent_area_id
      FROM administrative_areas
      WHERE id = ?
      LIMIT 1
    `,
    [adminAreaId],
  );
  if (!rows[0] || rows[0].area_type !== "upazila") {
    throw new BackendError(422, "AFFECTED_AREA_NOT_UPAZILA", "Affected area must be an upazila");
  }
  return rows[0];
}

async function insertDisasterStatusHistory(
  conn,
  { disasterEventId, statusId, actorUserId, note },
) {
  await conn.execute(
    `
      INSERT INTO disaster_event_status_history (
        disaster_event_id,
        status_id,
        changed_by_user_id,
        note
      )
      VALUES (?, ?, ?, ?)
    `,
    [disasterEventId, statusId, actorUserId ?? null, note ?? null],
  );
}

async function insertReliefRequestStatusHistory(
  conn,
  { reliefRequestId, statusId, actorUserId, note },
) {
  await conn.execute(
    `
      INSERT INTO relief_request_status_history (
        relief_request_id,
        status_id,
        changed_by_user_id,
        note
      )
      VALUES (?, ?, ?, ?)
    `,
    [reliefRequestId, statusId, actorUserId ?? null, note ?? null],
  );
}

function mapDisasterBasic(row) {
  return {
    public_uuid: row.public_uuid,
    event_code: row.event_code,
    title: row.title,
    description: row.description,
    public_guidance: row.public_guidance,
    severity_level: row.severity_level,
    status_code: row.status_code,
    event_type_code: row.event_type_code,
    event_type_name: row.event_type_name,
    started_at: row.started_at,
    ended_at: row.ended_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

async function countAffectedAreas(conn, disasterEventId) {
  const [rows] = await conn.execute(
    `
      SELECT COUNT(*) AS cnt
      FROM disaster_affected_areas
      WHERE disaster_event_id = ?
    `,
    [disasterEventId],
  );
  const cnt = rows[0]?.cnt;
  return typeof cnt === "bigint" ? Number(cnt) : Number(cnt ?? 0);
}

async function assertNoOpenLinkedIncidents(conn, disasterEventId) {
  const [rows] = await conn.execute(
    `
      SELECT ei.incident_code
      FROM disaster_incident_links dil
      INNER JOIN emergency_incidents ei ON ei.id = dil.incident_id
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      WHERE dil.disaster_event_id = ?
        AND dil.unlinked_at IS NULL
        AND ist.status_code NOT IN ('resolved', 'closed', 'cancelled')
      LIMIT 1
    `,
    [disasterEventId],
  );
  if (rows[0]) {
    throw new BackendError(
      409,
      "DISASTER_RESOLVE_BLOCKED_OPEN_INCIDENTS",
      "Cannot resolve or close disaster while linked incidents remain non-terminal",
    );
  }
}

async function assertNoOpenReliefRequests(conn, disasterEventId) {
  const [rows] = await conn.execute(
    `
      SELECT rr.request_code
      FROM relief_requests rr
      INNER JOIN relief_request_statuses rrs ON rrs.id = rr.current_status_id
      WHERE rr.disaster_event_id = ?
        AND rrs.status_code IN ('submitted', 'approved', 'partially_fulfilled')
      LIMIT 1
    `,
    [disasterEventId],
  );
  if (rows[0]) {
    throw new BackendError(
      409,
      "DISASTER_RESOLVE_BLOCKED_OPEN_RELIEF_REQUESTS",
      "Cannot resolve or close disaster while relief requests remain open",
    );
  }
}

async function finalizeActiveActivations(
  conn,
  disasterEventId,
  actorUserId,
  auditMeta,
) {
  const [shelters] = await conn.execute(
    `
      SELECT id
      FROM shelter_activations
      WHERE disaster_event_id = ?
        AND activation_status = 'active'
    `,
    [disasterEventId],
  );
  for (const sa of shelters) {
    await conn.execute(
      `
        UPDATE shelter_activations
        SET activation_status = 'finalized',
            finalized_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [sa.id],
    );
    await writeAudit(conn, {
      actorUserId,
      action: "shelter_activation.finalized",
      entityType: "shelter_activation",
      entityId: sa.id,
      relatedDisasterEventId: disasterEventId,
      detailsJson: { reason: "disaster_terminal_status" },
      auditMeta,
    });
  }

  const [hubs] = await conn.execute(
    `
      SELECT id
      FROM relief_hub_activations
      WHERE disaster_event_id = ?
        AND activation_status = 'active'
    `,
    [disasterEventId],
  );
  for (const hub of hubs) {
    await conn.execute(
      `
        UPDATE relief_hub_activations
        SET activation_status = 'finalized',
            finalized_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [hub.id],
    );
    await writeAudit(conn, {
      actorUserId,
      action: "relief_hub_activation.finalized",
      entityType: "relief_hub_activation",
      entityId: hub.id,
      relatedDisasterEventId: disasterEventId,
      detailsJson: { reason: "disaster_terminal_status" },
      auditMeta,
    });
  }
}

/**
 * Facilities with shelter/hub capabilities in affected upazilas or same district.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} disasterEventId
 * @param {{ onlyForNewUpazilaIds?: number[] }} [options]
 */
export async function findEligibleFacilitiesNearby(conn, disasterEventId, options = {}) {
  const params = [SHELTER_CAPABILITY, HUB_CAPABILITY, disasterEventId];
  let upazilaFilter = "";
  if (options.onlyForNewUpazilaIds?.length) {
    const placeholders = options.onlyForNewUpazilaIds.map(() => "?").join(", ");
    upazilaFilter = ` AND daa.admin_area_id IN (${placeholders})`;
    params.push(...options.onlyForNewUpazilaIds);
  }

  const [rows] = await conn.execute(
    `
      SELECT DISTINCT
        f.id AS facility_id,
        f.public_uuid AS facility_public_uuid,
        f.name AS facility_name,
        f.facility_code AS facility_code,
        cap.capability_code AS capability_code,
        l.admin_area_id AS location_admin_area_id
      FROM facilities f
      INNER JOIN locations l ON l.id = f.location_id
      INNER JOIN facility_capabilities fc ON fc.facility_id = f.id AND fc.is_active = TRUE
      INNER JOIN capabilities cap ON cap.id = fc.capability_id
      WHERE f.is_active = TRUE
        AND cap.capability_code IN (?, ?)
        AND EXISTS (
          SELECT 1
            FROM disaster_affected_areas daa
            INNER JOIN administrative_areas affected ON affected.id = daa.admin_area_id
            LEFT JOIN administrative_areas loc_area ON loc_area.id = l.admin_area_id
           WHERE daa.disaster_event_id = ?
             ${upazilaFilter}
             AND (
               l.admin_area_id = daa.admin_area_id
               OR loc_area.parent_area_id = affected.parent_area_id
             )
        )
    `,
    params,
  );

  return rows;
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 */
export async function runAutoActivations(
  conn,
  disasterEventId,
  actorUserId,
  auditMeta,
  options = {},
) {
  const facilities = await findEligibleFacilitiesNearby(conn, disasterEventId, options);

  for (const fac of facilities) {
    if (fac.capability_code === SHELTER_CAPABILITY) {
      try {
        const shelterUuid = randomUUID();
        const [result] = await conn.execute(
          `
            INSERT INTO shelter_activations (
              public_uuid,
              disaster_event_id,
              facility_id,
              activated_by_user_id,
              activation_source
            )
            VALUES (?, ?, ?, ?, 'auto')
          `,
          [shelterUuid, disasterEventId, fac.facility_id, actorUserId],
        );
        await writeAudit(conn, {
          actorUserId,
          action: "shelter_activation.auto_created",
          entityType: "shelter_activation",
          entityId: result.insertId,
          relatedDisasterEventId: disasterEventId,
          detailsJson: {
            facility_id: fac.facility_id,
            facility_public_uuid: fac.facility_public_uuid,
          },
          auditMeta,
        });
      } catch (err) {
        if (err.code !== "ER_DUP_ENTRY") throw err;
      }
    } else if (fac.capability_code === HUB_CAPABILITY) {
      try {
        const hubUuid = randomUUID();
        const [result] = await conn.execute(
          `
            INSERT INTO relief_hub_activations (
              public_uuid,
              disaster_event_id,
              facility_id,
              activated_by_user_id,
              activation_source
            )
            VALUES (?, ?, ?, ?, 'auto')
          `,
          [hubUuid, disasterEventId, fac.facility_id, actorUserId],
        );
        await writeAudit(conn, {
          actorUserId,
          action: "relief_hub_activation.auto_created",
          entityType: "relief_hub_activation",
          entityId: result.insertId,
          relatedDisasterEventId: disasterEventId,
          detailsJson: {
            facility_id: fac.facility_id,
            facility_public_uuid: fac.facility_public_uuid,
          },
          auditMeta,
        });
      } catch (err) {
        if (err.code !== "ER_DUP_ENTRY") throw err;
      }
    }
  }
}

async function assertFacilityHasCapability(conn, facilityId, capabilityCode) {
  const [rows] = await conn.execute(
    `
      SELECT 1
      FROM facility_capabilities fc
      INNER JOIN capabilities cap ON cap.id = fc.capability_id
      WHERE fc.facility_id = ?
        AND fc.is_active = TRUE
        AND cap.capability_code = ?
      LIMIT 1
    `,
    [facilityId, capabilityCode],
  );
  if (!rows[0]) {
    throw new BackendError(
      422,
      "FACILITY_MISSING_CAPABILITY",
      `Facility does not have required capability: ${capabilityCode}`,
    );
  }
}

async function isFacilityNearby(conn, disasterEventId, facilityId) {
  const [rows] = await conn.execute(
    `
      SELECT 1
      FROM facilities f
      INNER JOIN locations l ON l.id = f.location_id
      WHERE f.id = ?
        AND EXISTS (
          SELECT 1
            FROM disaster_affected_areas daa
            INNER JOIN administrative_areas affected ON affected.id = daa.admin_area_id
            LEFT JOIN administrative_areas loc_area ON loc_area.id = l.admin_area_id
           WHERE daa.disaster_event_id = ?
             AND (
               l.admin_area_id = daa.admin_area_id
               OR loc_area.parent_area_id = affected.parent_area_id
             )
        )
      LIMIT 1
    `,
    [facilityId, disasterEventId],
  );
  return Boolean(rows[0]);
}

async function insertAssessmentForArea(
  conn,
  { disasterAffectedAreaId, assessment, actorUserId },
) {
  if (!assessment) return;
  await conn.execute(
    `
      INSERT INTO disaster_affected_area_assessments (
        disaster_affected_area_id,
        impact_level,
        estimated_affected_people,
        shelter_support_required,
        relief_support_required,
        assessment_note,
        recorded_by_user_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      disasterAffectedAreaId,
      assessment.impactLevel ?? assessment.impact_level ?? "medium",
      assessment.estimatedAffectedPeople ??
        assessment.estimated_affected_people ??
        null,
      Boolean(
        assessment.shelterSupportRequired ?? assessment.shelter_support_required,
      ),
      Boolean(
        assessment.reliefSupportRequired ?? assessment.relief_support_required,
      ),
      assessment.assessmentNote ?? assessment.assessment_note ?? null,
      actorUserId,
    ],
  );
}

export async function createDisaster(params) {
  const title = String(params.title ?? "").trim();
  if (!title) {
    throw new BackendError(422, "DISASTER_TITLE_REQUIRED", "title is required");
  }
  if (!VALID_SEVERITY_LEVELS.has(params.severityLevel)) {
    throw new BackendError(422, "INVALID_SEVERITY_LEVEL", "Invalid severityLevel");
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const eventTypeId = await findDisasterEventTypeId(conn, params.eventTypeCode);
    const [statusRows] = await conn.execute(
      `
        SELECT id FROM disaster_event_statuses
        WHERE status_code = 'monitoring' AND is_active = TRUE
        LIMIT 1
      `,
    );
    const monitoringStatusId = statusRows[0].id;

    const publicUuid = randomUUID();
    const eventCode = generateCode("DST");

    const [insertResult] = await conn.execute(
      `
        INSERT INTO disaster_events (
          public_uuid,
          event_code,
          event_type_id,
          title,
          description,
          current_status_id,
          severity_level,
          started_at,
          created_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?)
      `,
      [
        publicUuid,
        eventCode,
        eventTypeId,
        title,
        params.description ?? null,
        monitoringStatusId,
        params.severityLevel,
        toMySqlDateTimeOrNull(params.startedAt),
        params.actorUserId,
      ],
    );

    const disasterEventId = insertResult.insertId;

    await insertDisasterStatusHistory(conn, {
      disasterEventId,
      statusId: monitoringStatusId,
      actorUserId: params.actorUserId,
      note: "Disaster event created",
    });

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "disaster_event.created",
      entityType: "disaster_event",
      entityId: disasterEventId,
      relatedDisasterEventId: disasterEventId,
      detailsJson: { event_code: eventCode, public_uuid: publicUuid },
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return getDisasterByPublicUuid(publicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

function buildDisasterListWhere(filters, params) {
  const clauses = [];
  if (filters.statusCode) {
    clauses.push("des.status_code = ?");
    params.push(filters.statusCode);
  }
  return clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
}

export async function listDisasters(filters = {}) {
  const limit = Math.min(
    Math.max(Number(filters.limit) || DEFAULT_DISASTER_LIMIT, 1),
    MAX_DISASTER_LIMIT,
  );
  const offset = Math.max(Number(filters.offset) || 0, 0);

  const filterParams = [];
  const whereSql = buildDisasterListWhere(filters, filterParams);

  const countSql = `
    SELECT COUNT(*) AS cnt
    FROM disaster_events de
    INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
    ${whereSql}
  `;

  const listSql = `
    SELECT
      de.public_uuid AS public_uuid,
      de.event_code AS event_code,
      de.title AS title,
      de.severity_level AS severity_level,
      de.started_at AS started_at,
      de.ended_at AS ended_at,
      de.created_at AS created_at,
      de.updated_at AS updated_at,
      des.status_code AS status_code,
      det.type_code AS event_type_code,
      det.name AS event_type_name
    FROM disaster_events de
    INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
    INNER JOIN disaster_event_types det ON det.id = de.event_type_id
    ${whereSql}
    ORDER BY de.started_at DESC, de.id DESC
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
    disasters: listResult.rows,
    pagination: { limit, offset, total },
  };
}

export async function getDisasterByPublicUuid(publicUuid) {
  const conn = await pool.getConnection();
  try {
    const row = await loadDisasterRow(conn, publicUuid);
    if (!row) {
      throw new BackendError(404, "DISASTER_NOT_FOUND", "Disaster event not found");
    }
    return mapDisasterBasic(row);
  } finally {
    conn.release();
  }
}

export async function getDisasterDashboard(publicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await requireDisaster(conn, publicUuid);
    const disasterEventId = disaster.id;

    const [statusHistory] = await conn.execute(
      `
        SELECT
          desh.id,
          des.status_code AS status_code,
          des.name AS status_name,
          desh.changed_at,
          desh.note,
          u.public_uuid AS changed_by_user_public_uuid
        FROM disaster_event_status_history desh
        INNER JOIN disaster_event_statuses des ON des.id = desh.status_id
        LEFT JOIN users u ON u.id = desh.changed_by_user_id
        WHERE desh.disaster_event_id = ?
        ORDER BY desh.changed_at ASC, desh.id ASC
      `,
      [disasterEventId],
    );

    const [declarations] = await conn.execute(
      `
        SELECT
          dd.public_uuid,
          dd.declaration_code,
          dd.declaration_kind,
          dd.title,
          dd.public_guidance,
          dd.legal_reference,
          dd.reason,
          dd.issued_at,
          u.public_uuid AS issued_by_user_public_uuid
        FROM disaster_declarations dd
        LEFT JOIN users u ON u.id = dd.issued_by_user_id
        WHERE dd.disaster_event_id = ?
        ORDER BY dd.issued_at ASC
      `,
      [disasterEventId],
    );

    const [affectedAreas] = await conn.execute(
      `
        SELECT
          daa.public_uuid AS affected_area_public_uuid,
          daa.admin_area_id,
          aa.name AS upazila_name,
          district.name AS district_name,
          division.name AS division_name,
          cur.impact_level,
          cur.estimated_affected_people,
          cur.shelter_support_required,
          cur.relief_support_required,
          cur.assessment_note,
          cur.recorded_at AS assessment_recorded_at
        FROM disaster_affected_areas daa
        INNER JOIN administrative_areas aa ON aa.id = daa.admin_area_id
        LEFT JOIN administrative_areas district ON district.id = aa.parent_area_id
        LEFT JOIN administrative_areas division ON division.id = district.parent_area_id
        LEFT JOIN vw_disaster_affected_area_current cur
          ON cur.disaster_affected_area_id = daa.id
        WHERE daa.disaster_event_id = ?
        ORDER BY district.name, aa.name
      `,
      [disasterEventId],
    );

    const [responsibilities] = await conn.execute(
      `
        SELECT
          dar.id,
          a.public_uuid AS agency_public_uuid,
          a.name AS agency_name,
          dar.responsibility_type,
          dar.is_lead,
          dar.assigned_at,
          dar.deactivated_at
        FROM disaster_agency_responsibilities dar
        INNER JOIN agencies a ON a.id = dar.agency_id
        WHERE dar.disaster_event_id = ?
          AND dar.deactivated_at IS NULL
        ORDER BY dar.responsibility_type, dar.is_lead DESC, a.name
      `,
      [disasterEventId],
    );

    const linkedIncidents = await listLinkedIncidents(publicUuid);

    const [shelters] = await conn.execute(
      `
        SELECT *
        FROM vw_disaster_shelter_capacity
        WHERE disaster_event_id = ?
        ORDER BY facility_name
      `,
      [disasterEventId],
    );

    const [reliefHubs] = await conn.execute(
      `
        SELECT
          rha.id AS relief_hub_activation_id,
          rha.public_uuid AS relief_hub_public_uuid,
          rha.activation_status,
          rha.activation_source,
          f.public_uuid AS facility_public_uuid,
          f.name AS facility_name
        FROM relief_hub_activations rha
        INNER JOIN facilities f ON f.id = rha.facility_id
        WHERE rha.disaster_event_id = ?
        ORDER BY f.name
      `,
      [disasterEventId],
    );

    const [inventory] = await conn.execute(
      `
        SELECT *
        FROM vw_disaster_relief_inventory_by_hub
        WHERE disaster_event_id = ?
        ORDER BY facility_name, item_code
      `,
      [disasterEventId],
    );

    const [reliefRequests] = await conn.execute(
      `
        SELECT
          rr.id AS relief_request_id,
          rr.public_uuid AS relief_request_public_uuid,
          rr.request_code,
          rrs.status_code AS status_code,
          sa.public_uuid AS shelter_activation_public_uuid,
          f.name AS shelter_facility_name
        FROM relief_requests rr
        INNER JOIN relief_request_statuses rrs ON rrs.id = rr.current_status_id
        INNER JOIN shelter_activations sa ON sa.id = rr.shelter_activation_id
        INNER JOIN facilities f ON f.id = sa.facility_id
        WHERE rr.disaster_event_id = ?
        ORDER BY rr.created_at DESC
      `,
      [disasterEventId],
    );

    const requestIds = reliefRequests.map((r) => r.relief_request_id);
    let shortages = [];
    if (requestIds.length) {
      const placeholders = requestIds.map(() => "?").join(", ");
      const [shortageRows] = await conn.execute(
        `
          SELECT *
          FROM vw_disaster_relief_shortage
          WHERE relief_request_id IN (${placeholders})
        `,
        requestIds,
      );
      shortages = shortageRows;
    }

    const [auditLogs] = await conn.execute(
      `
        SELECT
          al.id,
          al.action,
          al.entity_type,
          al.entity_id,
          al.details_json,
          al.created_at,
          u.public_uuid AS actor_user_public_uuid
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_user_id
        WHERE al.related_disaster_event_id = ?
        ORDER BY al.created_at DESC
        LIMIT 50
      `,
      [disasterEventId],
    );

    const [linkedIncidentCounts] = await conn.execute(
      `
        SELECT incident_status, incident_count
        FROM vw_disaster_linked_incidents
        WHERE disaster_event_id = ?
      `,
      [disasterEventId],
    );

    return {
      disaster: mapDisasterBasic(disaster),
      status_history: statusHistory,
      declarations,
      affected_areas: affectedAreas,
      responsibilities,
      linked_incidents: linkedIncidents,
      linked_incident_status_counts: linkedIncidentCounts,
      shelters,
      relief_hubs: reliefHubs,
      inventory_by_hub: inventory,
      relief_requests: reliefRequests.map((rr) => ({
        ...rr,
        shortages: shortages.filter((s) => s.relief_request_id === rr.relief_request_id),
      })),
      recent_audit_logs: auditLogs,
    };
  } finally {
    conn.release();
  }
}

export async function transitionDisasterStatus(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });
    const fromCode = disaster.status_code;
    const toCode = params.toStatusCode;

    if (toCode === "resolved" || toCode === "closed") {
      await assertNoOpenLinkedIncidents(conn, disaster.id);
      await assertNoOpenReliefRequests(conn, disaster.id);
    }

    const { toStatusId } = await assertStatusTransitionAllowed(
      conn,
      "disaster",
      fromCode,
      toCode,
      { note: params.note ?? null },
    );

    await insertDisasterStatusHistory(conn, {
      disasterEventId: disaster.id,
      statusId: toStatusId,
      actorUserId: params.actorUserId,
      note: params.note ?? null,
    });

    if (toCode === "closed" || toCode === "cancelled") {
      await finalizeActiveActivations(
        conn,
        disaster.id,
        params.actorUserId,
        params.auditMeta,
      );
    }

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "disaster_event.status_changed",
      entityType: "disaster_event",
      entityId: disaster.id,
      relatedDisasterEventId: disaster.id,
      detailsJson: { from_status: fromCode, to_status: toCode },
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return getDisasterByPublicUuid(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function addAffectedAreas(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });

    if (!AFFECTED_AREA_ALLOWED_STATUSES.has(disaster.status_code)) {
      throw new BackendError(
        409,
        "DISASTER_STATUS_BLOCKS_AFFECTED_AREAS",
        "Affected areas can only be added while disaster is monitoring or declared",
      );
    }

    let upazilaIds = [...(params.upazilaAdminAreaIds ?? [])].map(Number);

    if (params.districtAdminAreaId != null) {
      const expanded = await listUpazilaIdsUnderDistrict(
        conn,
        Number(params.districtAdminAreaId),
      );
      if (expanded === null) {
        throw new BackendError(422, "DISTRICT_BULK_INVALID", "Invalid district admin area");
      }
      upazilaIds.push(...expanded);
    }

    upazilaIds = [...new Set(upazilaIds.filter((id) => Number.isFinite(id) && id > 0))];
    if (!upazilaIds.length) {
      throw new BackendError(
        422,
        "AFFECTED_AREAS_REQUIRED",
        "At least one upazila or district is required",
      );
    }

    const newUpazilaIds = [];

    for (const adminAreaId of upazilaIds) {
      await assertUpazilaAdminArea(conn, adminAreaId);

      const [dup] = await conn.execute(
        `
          SELECT id FROM disaster_affected_areas
          WHERE disaster_event_id = ? AND admin_area_id = ?
          LIMIT 1
        `,
        [disaster.id, adminAreaId],
      );
      if (dup[0]) {
        throw new BackendError(
          409,
          "AFFECTED_AREA_DUPLICATE",
          "Upazila is already an affected area for this disaster",
        );
      }

      const areaUuid = randomUUID();
      const [areaResult] = await conn.execute(
        `
          INSERT INTO disaster_affected_areas (
            public_uuid,
            disaster_event_id,
            admin_area_id,
            added_by_user_id
          )
          VALUES (?, ?, ?, ?)
        `,
        [areaUuid, disaster.id, adminAreaId, params.actorUserId],
      );

      await insertAssessmentForArea(conn, {
        disasterAffectedAreaId: areaResult.insertId,
        assessment: params.assessment,
        actorUserId: params.actorUserId,
      });

      newUpazilaIds.push(adminAreaId);

      await writeAudit(conn, {
        actorUserId: params.actorUserId,
        action: "disaster.affected_area.added",
        entityType: "disaster_affected_area",
        entityId: areaResult.insertId,
        relatedDisasterEventId: disaster.id,
        detailsJson: { admin_area_id: adminAreaId, public_uuid: areaUuid },
        auditMeta: params.auditMeta,
      });
    }

    if (disaster.status_code === "declared" && newUpazilaIds.length) {
      await runAutoActivations(conn, disaster.id, params.actorUserId, params.auditMeta, {
        onlyForNewUpazilaIds: newUpazilaIds,
      });
    }

    await conn.commit();
    return getDisasterDashboard(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function updateAffectedAreaAssessment(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid);

    const [areaRows] = await conn.execute(
      `
        SELECT id
        FROM disaster_affected_areas
        WHERE public_uuid = ? AND disaster_event_id = ?
        LIMIT 1
      `,
      [params.affectedAreaPublicUuid, disaster.id],
    );
    if (!areaRows[0]) {
      throw new BackendError(404, "AFFECTED_AREA_NOT_FOUND", "Affected area not found");
    }

    await insertAssessmentForArea(conn, {
      disasterAffectedAreaId: areaRows[0].id,
      assessment: params.assessment,
      actorUserId: params.actorUserId,
    });

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "disaster.affected_area.assessment_updated",
      entityType: "disaster_affected_area",
      entityId: areaRows[0].id,
      relatedDisasterEventId: disaster.id,
      detailsJson: params.assessment,
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return getDisasterDashboard(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function assignResponsibility(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });
    const agency = await loadAgencyByPublicUuid(conn, params.agencyPublicUuid);
    if (!agency || !agency.is_active) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    if (params.isLead) {
      const [leadDup] = await conn.execute(
        `
          SELECT id
          FROM disaster_agency_responsibilities
          WHERE disaster_event_id = ?
            AND responsibility_type = ?
            AND is_lead = TRUE
            AND deactivated_at IS NULL
            AND agency_id <> ?
          LIMIT 1
        `,
        [disaster.id, params.responsibilityType, agency.id],
      );
      if (leadDup[0]) {
        throw new BackendError(
          409,
          "MULTIPLE_LEAD_AGENCIES",
          "Another agency is already lead for this responsibility type",
        );
      }
    }

    try {
      const [result] = await conn.execute(
        `
          INSERT INTO disaster_agency_responsibilities (
            disaster_event_id,
            agency_id,
            responsibility_type,
            is_lead,
            assigned_by_user_id
          )
          VALUES (?, ?, ?, ?, ?)
        `,
        [
          disaster.id,
          agency.id,
          params.responsibilityType,
          Boolean(params.isLead),
          params.actorUserId,
        ],
      );

      await writeAudit(conn, {
        actorUserId: params.actorUserId,
        action: "disaster.responsibility.assigned",
        entityType: "disaster_agency_responsibility",
        entityId: result.insertId,
        relatedDisasterEventId: disaster.id,
        detailsJson: {
          agency_public_uuid: params.agencyPublicUuid,
          responsibility_type: params.responsibilityType,
          is_lead: Boolean(params.isLead),
        },
        auditMeta: params.auditMeta,
      });
    } catch (err) {
      if (err.code === "ER_DUP_ENTRY") {
        throw new BackendError(
          409,
          "RESPONSIBILITY_DUPLICATE",
          "Agency already has this responsibility type for the disaster",
        );
      }
      throw err;
    }

    await conn.commit();
    return getDisasterDashboard(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function issueInitialDeclaration(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });

    if (disaster.status_code !== "monitoring") {
      throw new BackendError(
        409,
        "INVALID_STATUS_TRANSITION",
        "Initial declaration requires disaster in monitoring status",
      );
    }

    const areaCount = await countAffectedAreas(conn, disaster.id);
    if (areaCount === 0) {
      throw new BackendError(
        422,
        "DISASTER_DECLARE_WITHOUT_AFFECTED_AREAS",
        "Cannot issue initial declaration without affected areas",
      );
    }

    const [existingInitial] = await conn.execute(
      `
        SELECT id FROM disaster_declarations
        WHERE disaster_event_id = ? AND declaration_kind = 'initial'
        LIMIT 1
      `,
      [disaster.id],
    );
    if (existingInitial[0]) {
      throw new BackendError(
        409,
        "DISASTER_INITIAL_DECLARATION_EXISTS",
        "An initial declaration already exists for this disaster",
      );
    }

    const declarationUuid = randomUUID();
    const declarationCode = generateCode("DCL", 80);

    const [declResult] = await conn.execute(
      `
        INSERT INTO disaster_declarations (
          public_uuid,
          disaster_event_id,
          declaration_code,
          declaration_kind,
          title,
          public_guidance,
          legal_reference,
          reason,
          issued_by_user_id
        )
        VALUES (?, ?, ?, 'initial', ?, ?, ?, ?, ?)
      `,
      [
        declarationUuid,
        disaster.id,
        declarationCode,
        params.title.trim(),
        params.publicGuidance ?? null,
        params.legalReference ?? null,
        params.reason.trim(),
        params.actorUserId,
      ],
    );

    const { toStatusId } = await assertStatusTransitionAllowed(
      conn,
      "disaster",
      "monitoring",
      "declared",
      { note: params.reason },
    );

    await insertDisasterStatusHistory(conn, {
      disasterEventId: disaster.id,
      statusId: toStatusId,
      actorUserId: params.actorUserId,
      note: `Initial declaration ${declarationCode}`,
    });

    if (params.publicGuidance) {
      await conn.execute(
        `UPDATE disaster_events SET public_guidance = ? WHERE id = ?`,
        [params.publicGuidance, disaster.id],
      );
    }

    await runAutoActivations(conn, disaster.id, params.actorUserId, params.auditMeta);

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "disaster.declaration.initial",
      entityType: "disaster_declaration",
      entityId: declResult.insertId,
      relatedDisasterEventId: disaster.id,
      detailsJson: {
        declaration_code: declarationCode,
        public_uuid: declarationUuid,
      },
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return getDisasterDashboard(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function issueDeclarationAmendment(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid);

    const [initial] = await conn.execute(
      `
        SELECT id FROM disaster_declarations
        WHERE disaster_event_id = ? AND declaration_kind = 'initial'
        LIMIT 1
      `,
      [disaster.id],
    );
    if (!initial[0]) {
      throw new BackendError(
        422,
        "DISASTER_AMENDMENT_WITHOUT_INITIAL",
        "Cannot issue amendment without an initial declaration",
      );
    }

    const declarationUuid = randomUUID();
    const declarationCode = generateCode("DCL", 80);

    const [declResult] = await conn.execute(
      `
        INSERT INTO disaster_declarations (
          public_uuid,
          disaster_event_id,
          declaration_code,
          declaration_kind,
          title,
          public_guidance,
          legal_reference,
          reason,
          issued_by_user_id
        )
        VALUES (?, ?, ?, 'amendment', ?, ?, ?, ?, ?)
      `,
      [
        declarationUuid,
        disaster.id,
        declarationCode,
        params.title.trim(),
        params.publicGuidance ?? null,
        params.legalReference ?? null,
        params.reason.trim(),
        params.actorUserId,
      ],
    );

    if (params.publicGuidance) {
      await conn.execute(
        `UPDATE disaster_events SET public_guidance = ? WHERE id = ?`,
        [params.publicGuidance, disaster.id],
      );
    }

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "disaster.declaration.amendment",
      entityType: "disaster_declaration",
      entityId: declResult.insertId,
      relatedDisasterEventId: disaster.id,
      detailsJson: {
        declaration_code: declarationCode,
        public_uuid: declarationUuid,
      },
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return getDisasterDashboard(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function manualActivateShelter(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });
    const facility = await loadFacilityByPublicUuid(conn, params.facilityPublicUuid);
    if (!facility || !facility.is_active) {
      throw new BackendError(404, "FACILITY_NOT_FOUND", "Facility not found");
    }

    await assertFacilityHasCapability(conn, facility.id, SHELTER_CAPABILITY);

    const nearby = await isFacilityNearby(conn, disaster.id, facility.id);
    if (!nearby) {
      const note = params.manualOverrideNote ?? params.manual_override_note;
      if (!note || !String(note).trim()) {
        throw new BackendError(
          422,
          "MANUAL_ACTIVATION_NOTE_REQUIRED",
          "manualOverrideNote is required when facility is outside affected/nearby areas",
        );
      }
    }

    const shelterUuid = randomUUID();
    let insertId;
    try {
      const [result] = await conn.execute(
        `
          INSERT INTO shelter_activations (
            public_uuid,
            disaster_event_id,
            facility_id,
            activated_by_user_id,
            activation_source,
            manual_override_note,
            usable_capacity_override
          )
          VALUES (?, ?, ?, ?, 'manual', ?, ?)
        `,
        [
          shelterUuid,
          disaster.id,
          facility.id,
          params.actorUserId,
          nearby ? null : (params.manualOverrideNote ?? params.manual_override_note),
          params.usableCapacityOverride ?? params.usable_capacity_override ?? null,
        ],
      );
      insertId = result.insertId;
    } catch (err) {
      if (err.code === "ER_DUP_ENTRY") {
        throw new BackendError(
          409,
          "SHELTER_ALREADY_ACTIVATED",
          "Shelter is already activated for this disaster",
        );
      }
      throw err;
    }

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "shelter_activation.manual_created",
      entityType: "shelter_activation",
      entityId: insertId,
      relatedDisasterEventId: disaster.id,
      detailsJson: { facility_public_uuid: params.facilityPublicUuid, nearby },
      auditMeta: params.auditMeta,
    });

    await conn.commit();

    const [rows] = await conn.execute(
      `SELECT * FROM vw_disaster_shelter_capacity WHERE shelter_activation_id = ?`,
      [insertId],
    );
    return rows[0];
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function manualActivateReliefHub(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });
    const facility = await loadFacilityByPublicUuid(conn, params.facilityPublicUuid);
    if (!facility || !facility.is_active) {
      throw new BackendError(404, "FACILITY_NOT_FOUND", "Facility not found");
    }

    await assertFacilityHasCapability(conn, facility.id, HUB_CAPABILITY);

    const nearby = await isFacilityNearby(conn, disaster.id, facility.id);
    if (!nearby) {
      const note = params.manualOverrideNote ?? params.manual_override_note;
      if (!note || !String(note).trim()) {
        throw new BackendError(
          422,
          "MANUAL_ACTIVATION_NOTE_REQUIRED",
          "manualOverrideNote is required when facility is outside affected/nearby areas",
        );
      }
    }

    const hubUuid = randomUUID();
    let insertId;
    try {
      const [result] = await conn.execute(
        `
          INSERT INTO relief_hub_activations (
            public_uuid,
            disaster_event_id,
            facility_id,
            activated_by_user_id,
            activation_source,
            manual_override_note
          )
          VALUES (?, ?, ?, ?, 'manual', ?)
        `,
        [
          hubUuid,
          disaster.id,
          facility.id,
          params.actorUserId,
          nearby ? null : (params.manualOverrideNote ?? params.manual_override_note),
        ],
      );
      insertId = result.insertId;
    } catch (err) {
      if (err.code === "ER_DUP_ENTRY") {
        throw new BackendError(
          409,
          "RELIEF_HUB_ALREADY_ACTIVATED",
          "Relief hub is already activated for this disaster",
        );
      }
      throw err;
    }

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "relief_hub_activation.manual_created",
      entityType: "relief_hub_activation",
      entityId: insertId,
      relatedDisasterEventId: disaster.id,
      detailsJson: { facility_public_uuid: params.facilityPublicUuid, nearby },
      auditMeta: params.auditMeta,
    });

    await conn.commit();

    const [rows] = await conn.execute(
      `
        SELECT rha.*, f.name AS facility_name, f.public_uuid AS facility_public_uuid
        FROM relief_hub_activations rha
        INNER JOIN facilities f ON f.id = rha.facility_id
        WHERE rha.id = ?
      `,
      [insertId],
    );
    return rows[0];
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function linkIncident(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });

    if (DISASTER_LINK_BLOCKED_STATUSES.has(disaster.status_code)) {
      throw new BackendError(
        409,
        "DISASTER_LINK_INCIDENT_TERMINAL_STATUS",
        "Cannot link incidents to a terminal disaster",
      );
    }

    const [incRows] = await conn.execute(
      `
        SELECT ei.id, ei.incident_code, ist.status_code
        FROM emergency_incidents ei
        INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
        WHERE ei.public_uuid = ?
        LIMIT 1
      `,
      [params.incidentPublicUuid],
    );
    if (!incRows[0]) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }

    const [activeElsewhere] = await conn.execute(
      `
        SELECT dil.id
        FROM disaster_incident_links dil
        WHERE dil.incident_id = ?
          AND dil.unlinked_at IS NULL
          AND dil.disaster_event_id <> ?
        LIMIT 1
      `,
      [incRows[0].id, disaster.id],
    );
    if (activeElsewhere[0]) {
      throw new BackendError(
        409,
        "INCIDENT_ALREADY_LINKED_TO_DISASTER",
        "Incident is already linked to another disaster",
      );
    }

    const [existing] = await conn.execute(
      `
        SELECT id FROM disaster_incident_links
        WHERE disaster_event_id = ? AND incident_id = ? AND unlinked_at IS NULL
        LIMIT 1
      `,
      [disaster.id, incRows[0].id],
    );
    if (existing[0]) {
      return listLinkedIncidents(params.disasterPublicUuid);
    }

    const [linkResult] = await conn.execute(
      `
        INSERT INTO disaster_incident_links (
          disaster_event_id,
          incident_id,
          linked_by_user_id,
          link_note
        )
        VALUES (?, ?, ?, ?)
      `,
      [disaster.id, incRows[0].id, params.actorUserId, params.linkNote ?? null],
    );

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "disaster.incident.linked",
      entityType: "disaster_incident_link",
      entityId: linkResult.insertId,
      relatedDisasterEventId: disaster.id,
      detailsJson: {
        incident_public_uuid: params.incidentPublicUuid,
        incident_code: incRows[0].incident_code,
      },
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return listLinkedIncidents(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function unlinkIncident(params) {
  const reason = params.reason ?? params.unlinkReason;
  if (!reason || !String(reason).trim()) {
    throw new BackendError(422, "UNLINK_REASON_REQUIRED", "Unlink reason is required");
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });

    const [linkRows] = await conn.execute(
      `
        SELECT dil.id
        FROM disaster_incident_links dil
        INNER JOIN emergency_incidents ei ON ei.id = dil.incident_id
        WHERE dil.disaster_event_id = ?
          AND ei.public_uuid = ?
          AND dil.unlinked_at IS NULL
        LIMIT 1
      `,
      [disaster.id, params.incidentPublicUuid],
    );
    if (!linkRows[0]) {
      throw new BackendError(404, "DISASTER_INCIDENT_LINK_NOT_FOUND", "Active link not found");
    }

    await conn.execute(
      `
        UPDATE disaster_incident_links
        SET unlinked_at = CURRENT_TIMESTAMP,
            unlinked_by_user_id = ?,
            unlink_reason = ?
        WHERE id = ?
      `,
      [params.actorUserId, reason.trim(), linkRows[0].id],
    );

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "disaster.incident.unlinked",
      entityType: "disaster_incident_link",
      entityId: linkRows[0].id,
      relatedDisasterEventId: disaster.id,
      detailsJson: {
        incident_public_uuid: params.incidentPublicUuid,
        reason: reason.trim(),
      },
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return listLinkedIncidents(params.disasterPublicUuid);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function listLinkedIncidents(disasterPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await requireDisaster(conn, disasterPublicUuid);

    const [rows] = await conn.execute(
      `
        SELECT
          ei.public_uuid AS incident_public_uuid,
          ei.incident_code,
          ei.title,
          ist.status_code AS incident_status,
          dil.linked_at,
          dil.link_note,
          l.admin_area_id AS location_admin_area_id,
          aa.name AS location_upazila_name
        FROM disaster_incident_links dil
        INNER JOIN emergency_incidents ei ON ei.id = dil.incident_id
        INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
        LEFT JOIN locations l ON l.id = ei.current_location_id
        LEFT JOIN administrative_areas aa ON aa.id = l.admin_area_id
        WHERE dil.disaster_event_id = ?
          AND dil.unlinked_at IS NULL
        ORDER BY dil.linked_at DESC
      `,
      [disaster.id],
    );
    return rows;
  } finally {
    conn.release();
  }
}

export async function listCandidateIncidents(disasterPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await requireDisaster(conn, disasterPublicUuid);

    const [rows] = await conn.execute(
      `
        SELECT
          ei.public_uuid AS incident_public_uuid,
          ei.incident_code,
          ei.title,
          ist.status_code AS incident_status,
          ei.reported_at,
          l.admin_area_id AS location_admin_area_id,
          aa.name AS location_upazila_name,
          CASE
            WHEN l.admin_area_id IN (
              SELECT daa.admin_area_id
                FROM disaster_affected_areas daa
               WHERE daa.disaster_event_id = ?
            ) THEN 1
            ELSE 0
          END AS in_affected_upazila
        FROM emergency_incidents ei
        INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
        LEFT JOIN locations l ON l.id = ei.current_location_id
        LEFT JOIN administrative_areas aa ON aa.id = l.admin_area_id
        WHERE ist.is_terminal = FALSE
          AND NOT EXISTS (
            SELECT 1
              FROM disaster_incident_links dil
             WHERE dil.incident_id = ei.id
               AND dil.unlinked_at IS NULL
          )
        ORDER BY in_affected_upazila DESC, ei.reported_at DESC
        LIMIT 100
      `,
      [disaster.id],
    );
    return rows;
  } finally {
    conn.release();
  }
}

export async function assignShelterManagingAgency(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid);
    const agency = await loadAgencyByPublicUuid(conn, params.agencyPublicUuid);
    if (!agency || !agency.is_active) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    const [resp] = await conn.execute(
      `
        SELECT id
        FROM disaster_agency_responsibilities
        WHERE disaster_event_id = ?
          AND agency_id = ?
          AND responsibility_type = 'shelter_management'
          AND deactivated_at IS NULL
        LIMIT 1
      `,
      [disaster.id, agency.id],
    );
    if (!resp[0]) {
      throw new BackendError(
        409,
        "SHELTER_MANAGER_LACKS_RESPONSIBILITY",
        "Agency does not have shelter_management responsibility for this disaster",
      );
    }

    const [saRows] = await conn.execute(
      `
        SELECT sa.id
        FROM shelter_activations sa
        WHERE sa.public_uuid = ? AND sa.disaster_event_id = ?
        LIMIT 1
      `,
      [params.shelterActivationPublicUuid, disaster.id],
    );
    if (!saRows[0]) {
      throw new BackendError(404, "SHELTER_ACTIVATION_NOT_FOUND", "Shelter activation not found");
    }

    await conn.execute(
      `
        UPDATE shelter_activations
        SET managing_agency_id = ?
        WHERE id = ?
      `,
      [agency.id, saRows[0].id],
    );

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "shelter_activation.managing_agency_assigned",
      entityType: "shelter_activation",
      entityId: saRows[0].id,
      relatedDisasterEventId: disaster.id,
      detailsJson: { agency_public_uuid: params.agencyPublicUuid },
      auditMeta: params.auditMeta,
    });

    await conn.commit();

    const [viewRow] = await conn.execute(
      `SELECT * FROM vw_disaster_shelter_capacity WHERE shelter_activation_id = ?`,
      [saRows[0].id],
    );
    return viewRow[0];
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function recordShelterOccupancy(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid);

    const [saRows] = await conn.execute(
      `
        SELECT sa.id, sa.activation_status
        FROM shelter_activations sa
        WHERE sa.public_uuid = ? AND sa.disaster_event_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [params.shelterActivationPublicUuid, disaster.id],
    );
    if (!saRows[0]) {
      throw new BackendError(404, "SHELTER_ACTIVATION_NOT_FOUND", "Shelter activation not found");
    }
    if (saRows[0].activation_status !== "active") {
      throw new BackendError(409, "SHELTER_NOT_ACTIVE", "Shelter activation is not active");
    }

    const peopleCount = Number(params.peopleCount ?? params.people_count ?? 0);
    if (!Number.isFinite(peopleCount) || peopleCount < 0) {
      throw new BackendError(422, "INVALID_OCCUPANCY", "peopleCount must be a non-negative number");
    }

    const [snapResult] = await conn.execute(
      `
        INSERT INTO shelter_occupancy_snapshots (
          shelter_activation_id,
          people_count,
          recorded_by_user_id
        )
        VALUES (?, ?, ?)
      `,
      [saRows[0].id, peopleCount, params.actorUserId],
    );

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "shelter_activation.occupancy_recorded",
      entityType: "shelter_occupancy_snapshot",
      entityId: snapResult.insertId,
      relatedDisasterEventId: disaster.id,
      detailsJson: { people_count: peopleCount },
      auditMeta: params.auditMeta,
    });

    await conn.commit();

    const [viewRow] = await conn.execute(
      `SELECT * FROM vw_disaster_shelter_capacity WHERE shelter_activation_id = ?`,
      [saRows[0].id],
    );
    return viewRow[0];
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function recordStockReceipt(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid);

    const [hubRows] = await conn.execute(
      `
        SELECT rha.id, rha.activation_status
        FROM relief_hub_activations rha
        WHERE rha.public_uuid = ? AND rha.disaster_event_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [params.reliefHubActivationPublicUuid, disaster.id],
    );
    if (!hubRows[0]) {
      throw new BackendError(404, "RELief_HUB_NOT_FOUND", "Relief hub activation not found");
    }
    if (hubRows[0].activation_status !== "active") {
      throw new BackendError(
        409,
        "RELief_STOCK_RECEIPT_INACTIVE_HUB",
        "Cannot record stock for a non-active relief hub",
      );
    }

    const [itemRows] = await conn.execute(
      `
        SELECT id FROM relief_items
        WHERE item_code = ? AND is_active = TRUE
        LIMIT 1
      `,
      [params.itemCode ?? params.item_code],
    );
    if (!itemRows[0]) {
      throw new BackendError(404, "RELief_ITEM_NOT_FOUND", "Relief item not found");
    }

    const qty = Number(params.quantityReceived ?? params.quantity_received);
    if (!Number.isFinite(qty) || qty <= 0) {
      throw new BackendError(422, "INVALID_QUANTITY", "quantityReceived must be positive");
    }

    const receiptUuid = randomUUID();
    const [receiptResult] = await conn.execute(
      `
        INSERT INTO relief_stock_receipts (
          public_uuid,
          relief_hub_activation_id,
          relief_item_id,
          quantity_received,
          received_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        receiptUuid,
        hubRows[0].id,
        itemRows[0].id,
        qty,
        params.actorUserId,
        params.note ?? null,
      ],
    );

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "relief.stock_received",
      entityType: "relief_stock_receipt",
      entityId: receiptResult.insertId,
      relatedDisasterEventId: disaster.id,
      detailsJson: {
        item_code: params.itemCode ?? params.item_code,
        quantity_received: qty,
      },
      auditMeta: params.auditMeta,
    });

    await conn.commit();

    return {
      public_uuid: receiptUuid,
      relief_hub_activation_id: hubRows[0].id,
      relief_item_id: itemRows[0].id,
      quantity_received: qty,
    };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

async function loadReliefRequest(conn, publicUuid, disasterEventId) {
  const [rows] = await conn.execute(
    `
      SELECT
        rr.id,
        rr.public_uuid,
        rr.request_code,
        rr.disaster_event_id,
        rr.shelter_activation_id,
        rrs.status_code AS status_code
      FROM relief_requests rr
      INNER JOIN relief_request_statuses rrs ON rrs.id = rr.current_status_id
      WHERE rr.public_uuid = ?
        AND rr.disaster_event_id = ?
      LIMIT 1
      FOR UPDATE
    `,
    [publicUuid, disasterEventId],
  );
  return rows[0] || null;
}

async function computeHubItemAvailable(conn, hubActivationId, reliefItemId) {
  const [rows] = await conn.execute(
    `
      SELECT
        COALESCE((
          SELECT SUM(rsr.quantity_received)
          FROM relief_stock_receipts rsr
          WHERE rsr.relief_hub_activation_id = ?
            AND rsr.relief_item_id = ?
        ), 0)
        - COALESCE((
          SELECT SUM(rdi.quantity_delivered)
          FROM relief_distributions rd
          INNER JOIN relief_distribution_items rdi ON rdi.relief_distribution_id = rd.id
          WHERE rd.source_hub_activation_id = ?
            AND rdi.relief_item_id = ?
        ), 0) AS available
    `,
    [hubActivationId, reliefItemId, hubActivationId, reliefItemId],
  );
  const val = rows[0]?.available;
  return typeof val === "bigint" ? Number(val) : Number(val ?? 0);
}

async function syncReliefRequestStatusFromDeliveries(
  conn,
  reliefRequestId,
  actorUserId,
  note,
) {
  const [reqRows] = await conn.execute(
    `
      SELECT rrs.status_code
      FROM relief_requests rr
      INNER JOIN relief_request_statuses rrs ON rrs.id = rr.current_status_id
      WHERE rr.id = ?
      LIMIT 1
    `,
    [reliefRequestId],
  );
  const currentStatus = reqRows[0]?.status_code;
  if (!currentStatus || currentStatus === "rejected" || currentStatus === "fulfilled") {
    return currentStatus;
  }

  const [itemRows] = await conn.execute(
    `
      SELECT
        rri.relief_item_id,
        rri.quantity_requested,
        COALESCE(del.total_delivered, 0) AS total_delivered
      FROM relief_request_items rri
      LEFT JOIN (
        SELECT rdi.relief_item_id, SUM(rdi.quantity_delivered) AS total_delivered
        FROM relief_distributions rd
        INNER JOIN relief_distribution_items rdi ON rdi.relief_distribution_id = rd.id
        WHERE rd.relief_request_id = ?
        GROUP BY rdi.relief_item_id
      ) del ON del.relief_item_id = rri.relief_item_id
      WHERE rri.relief_request_id = ?
    `,
    [reliefRequestId, reliefRequestId],
  );

  if (!itemRows.length) return currentStatus;

  let allFulfilled = true;
  let anyDelivered = false;
  for (const item of itemRows) {
    const delivered = Number(item.total_delivered);
    const requested = Number(item.quantity_requested);
    if (delivered > 0) anyDelivered = true;
    if (delivered < requested) allFulfilled = false;
  }

  let targetStatus = currentStatus;
  if (allFulfilled && anyDelivered) {
    targetStatus = "fulfilled";
  } else if (anyDelivered) {
    targetStatus = "partially_fulfilled";
  }

  if (targetStatus === currentStatus) return currentStatus;

  const { toStatusId } = await assertStatusTransitionAllowed(
    conn,
    "relief_request",
    currentStatus,
    targetStatus,
    { note },
  );

  await insertReliefRequestStatusHistory(conn, {
    reliefRequestId,
    statusId: toStatusId,
    actorUserId,
    note: note ?? "Status derived from distribution totals",
  });

  return targetStatus;
}

export async function createReliefRequest(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });

    const [saRows] = await conn.execute(
      `
        SELECT sa.id, sa.activation_status
        FROM shelter_activations sa
        WHERE sa.public_uuid = ? AND sa.disaster_event_id = ?
        LIMIT 1
      `,
      [params.shelterActivationPublicUuid, disaster.id],
    );
    if (!saRows[0]) {
      throw new BackendError(404, "SHELTER_ACTIVATION_NOT_FOUND", "Shelter activation not found");
    }
    if (saRows[0].activation_status !== "active") {
      throw new BackendError(409, "SHELTER_NOT_ACTIVE", "Shelter activation is not active");
    }

    const [submittedStatus] = await conn.execute(
      `
        SELECT id FROM relief_request_statuses
        WHERE status_code = 'submitted' AND is_active = TRUE
        LIMIT 1
      `,
    );

    let requestingAgencyId = null;
    if (params.requestingAgencyPublicUuid) {
      const agency = await loadAgencyByPublicUuid(conn, params.requestingAgencyPublicUuid);
      if (!agency) {
        throw new BackendError(404, "AGENCY_NOT_FOUND", "Requesting agency not found");
      }
      requestingAgencyId = agency.id;
    }

    const requestUuid = randomUUID();
    const requestCode = generateCode("RRQ", 80);

    const [reqResult] = await conn.execute(
      `
        INSERT INTO relief_requests (
          public_uuid,
          request_code,
          disaster_event_id,
          shelter_activation_id,
          current_status_id,
          requested_by_user_id,
          requesting_agency_id,
          request_note
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        requestUuid,
        requestCode,
        disaster.id,
        saRows[0].id,
        submittedStatus[0].id,
        params.actorUserId,
        requestingAgencyId,
        params.requestNote ?? params.request_note ?? null,
      ],
    );

    const reliefRequestId = reqResult.insertId;

    await insertReliefRequestStatusHistory(conn, {
      reliefRequestId,
      statusId: submittedStatus[0].id,
      actorUserId: params.actorUserId,
      note: "Relief request submitted",
    });

    const items = params.items ?? [];
    for (const item of items) {
      const itemCode = item.itemCode ?? item.item_code;
      const qty = Number(item.quantityRequested ?? item.quantity_requested);
      if (!itemCode || !Number.isFinite(qty) || qty <= 0) {
        throw new BackendError(422, "INVALID_REQUEST_ITEM", "Each item requires itemCode and positive quantityRequested");
      }
      const [itemRows] = await conn.execute(
        `SELECT id FROM relief_items WHERE item_code = ? AND is_active = TRUE LIMIT 1`,
        [itemCode],
      );
      if (!itemRows[0]) {
        throw new BackendError(404, "RELief_ITEM_NOT_FOUND", `Relief item not found: ${itemCode}`);
      }
      await conn.execute(
        `
          INSERT INTO relief_request_items (relief_request_id, relief_item_id, quantity_requested, note)
          VALUES (?, ?, ?, ?)
        `,
        [reliefRequestId, itemRows[0].id, qty, item.note ?? null],
      );
    }

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "relief.request.created",
      entityType: "relief_request",
      entityId: reliefRequestId,
      relatedDisasterEventId: disaster.id,
      detailsJson: { request_code: requestCode, public_uuid: requestUuid },
      auditMeta: params.auditMeta,
    });

    await conn.commit();

    return {
      public_uuid: requestUuid,
      request_code: requestCode,
      status_code: "submitted",
    };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function approveReliefRequest(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid);
    const request = await loadReliefRequest(
      conn,
      params.reliefRequestPublicUuid,
      disaster.id,
    );
    if (!request) {
      throw new BackendError(404, "RELief_REQUEST_NOT_FOUND", "Relief request not found");
    }

    const { toStatusId } = await assertStatusTransitionAllowed(
      conn,
      "relief_request",
      request.status_code,
      "approved",
      { note: params.note ?? null },
    );

    await insertReliefRequestStatusHistory(conn, {
      reliefRequestId: request.id,
      statusId: toStatusId,
      actorUserId: params.actorUserId,
      note: params.note ?? null,
    });

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "relief.request.approved",
      entityType: "relief_request",
      entityId: request.id,
      relatedDisasterEventId: disaster.id,
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return { public_uuid: request.public_uuid, status_code: "approved" };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function rejectReliefRequest(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid);
    const request = await loadReliefRequest(
      conn,
      params.reliefRequestPublicUuid,
      disaster.id,
    );
    if (!request) {
      throw new BackendError(404, "RELief_REQUEST_NOT_FOUND", "Relief request not found");
    }

    const { toStatusId } = await assertStatusTransitionAllowed(
      conn,
      "relief_request",
      request.status_code,
      "rejected",
      { note: params.note ?? params.reason },
    );

    await insertReliefRequestStatusHistory(conn, {
      reliefRequestId: request.id,
      statusId: toStatusId,
      actorUserId: params.actorUserId,
      note: params.note ?? params.reason,
    });

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "relief.request.rejected",
      entityType: "relief_request",
      entityId: request.id,
      relatedDisasterEventId: disaster.id,
      auditMeta: params.auditMeta,
    });

    await conn.commit();
    return { public_uuid: request.public_uuid, status_code: "rejected" };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function createReliefDistribution(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const disaster = await requireDisaster(conn, params.disasterPublicUuid, {
      forUpdate: true,
    });

    const request = await loadReliefRequest(
      conn,
      params.reliefRequestPublicUuid,
      disaster.id,
    );
    if (!request) {
      throw new BackendError(404, "RELief_REQUEST_NOT_FOUND", "Relief request not found");
    }

    if (request.status_code === "rejected" || request.status_code === "fulfilled") {
      throw new BackendError(
        409,
        "RELief_REQUEST_NOT_DISTRIBUTABLE",
        "Cannot distribute for a terminal relief request",
      );
    }

    const [hubRows] = await conn.execute(
      `
        SELECT id, activation_status
        FROM relief_hub_activations
        WHERE public_uuid = ? AND disaster_event_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [params.sourceHubActivationPublicUuid, disaster.id],
    );
    if (!hubRows[0] || hubRows[0].activation_status !== "active") {
      throw new BackendError(
        409,
        "RELief_STOCK_RECEIPT_INACTIVE_HUB",
        "Source relief hub is not active",
      );
    }

    const [destShelter] = await conn.execute(
      `
        SELECT id, activation_status
        FROM shelter_activations
        WHERE id = ?
        LIMIT 1
      `,
      [request.shelter_activation_id],
    );
    if (!destShelter[0] || destShelter[0].activation_status !== "active") {
      throw new BackendError(409, "SHELTER_NOT_ACTIVE", "Destination shelter is not active");
    }

    if (request.status_code === "submitted") {
      const { toStatusId: approvedId } = await assertStatusTransitionAllowed(
        conn,
        "relief_request",
        "submitted",
        "approved",
        { note: "Auto-approved on first distribution" },
      );
      await insertReliefRequestStatusHistory(conn, {
        reliefRequestId: request.id,
        statusId: approvedId,
        actorUserId: params.actorUserId,
        note: "Auto-approved on first distribution",
      });
      request.status_code = "approved";
    }

    const distributionUuid = randomUUID();
    const distributionCode = generateCode("RDT", 80);

    const [distResult] = await conn.execute(
      `
        INSERT INTO relief_distributions (
          public_uuid,
          distribution_code,
          relief_request_id,
          source_hub_activation_id,
          destination_shelter_activation_id,
          distributed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      [
        distributionUuid,
        distributionCode,
        request.id,
        hubRows[0].id,
        request.shelter_activation_id,
        params.actorUserId,
        params.note ?? null,
      ],
    );

    const distributionId = distResult.insertId;
    const items = params.items ?? [];

    for (const item of items) {
      const itemCode = item.itemCode ?? item.item_code;
      const qty = Number(item.quantityDelivered ?? item.quantity_delivered);
      if (!itemCode || !Number.isFinite(qty) || qty <= 0) {
        throw new BackendError(
          422,
          "INVALID_DISTRIBUTION_ITEM",
          "Each item requires itemCode and positive quantityDelivered",
        );
      }

      const [itemRows] = await conn.execute(
        `SELECT id FROM relief_items WHERE item_code = ? AND is_active = TRUE LIMIT 1`,
        [itemCode],
      );
      if (!itemRows[0]) {
        throw new BackendError(404, "RELief_ITEM_NOT_FOUND", `Relief item not found: ${itemCode}`);
      }

      const available = await computeHubItemAvailable(
        conn,
        hubRows[0].id,
        itemRows[0].id,
      );
      if (qty > available) {
        throw new BackendError(
          409,
          "INSUFFICIENT_INVENTORY",
          `Insufficient inventory for item ${itemCode}`,
        );
      }

      const [reqItem] = await conn.execute(
        `
          SELECT rri.quantity_requested,
                 COALESCE(del.total_delivered, 0) AS already_delivered
          FROM relief_request_items rri
          LEFT JOIN (
            SELECT rdi.relief_item_id, SUM(rdi.quantity_delivered) AS total_delivered
            FROM relief_distributions rd
            INNER JOIN relief_distribution_items rdi ON rdi.relief_distribution_id = rd.id
            WHERE rd.relief_request_id = ?
            GROUP BY rdi.relief_item_id
          ) del ON del.relief_item_id = rri.relief_item_id
          WHERE rri.relief_request_id = ? AND rri.relief_item_id = ?
          LIMIT 1
        `,
        [request.id, request.id, itemRows[0].id],
      );

      if (reqItem[0]) {
        const remaining =
          Number(reqItem[0].quantity_requested) - Number(reqItem[0].already_delivered);
        if (qty > remaining) {
          throw new BackendError(
            409,
            "DISTRIBUTION_EXCEEDS_REQUEST",
            `Distribution quantity exceeds remaining request for ${itemCode}`,
          );
        }
      }

      await conn.execute(
        `
          INSERT INTO relief_distribution_items (
            relief_distribution_id,
            relief_item_id,
            quantity_delivered
          )
          VALUES (?, ?, ?)
        `,
        [distributionId, itemRows[0].id, qty],
      );
    }

    const newStatus = await syncReliefRequestStatusFromDeliveries(
      conn,
      request.id,
      params.actorUserId,
      `Distribution ${distributionCode}`,
    );

    await writeAudit(conn, {
      actorUserId: params.actorUserId,
      action: "relief.distributed",
      entityType: "relief_distribution",
      entityId: distributionId,
      relatedDisasterEventId: disaster.id,
      detailsJson: {
        distribution_code: distributionCode,
        relief_request_public_uuid: params.reliefRequestPublicUuid,
        status_code: newStatus,
      },
      auditMeta: params.auditMeta,
    });

    await conn.commit();

    return {
      public_uuid: distributionUuid,
      distribution_code: distributionCode,
      relief_request_status: newStatus,
    };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function listPublicDisasters() {
  const { rows } = await query(
    `
      SELECT *
      FROM vw_public_disaster_summary
      ORDER BY started_at DESC
    `,
  );
  return rows;
}

export async function getPublicDisasterSummary(publicUuid) {
  const { rows } = await query(
    `
      SELECT *
      FROM vw_public_disaster_summary
      WHERE disaster_public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  if (!rows[0]) {
    const [anyRow] = await pool.query(
      `
        SELECT des.status_code
        FROM disaster_events de
        INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
        WHERE de.public_uuid = ?
        LIMIT 1
      `,
      [publicUuid],
    );
    if (anyRow[0]) {
      throw new BackendError(404, "DISASTER_NOT_PUBLIC", "Disaster is not publicly visible");
    }
    throw new BackendError(404, "DISASTER_NOT_FOUND", "Disaster event not found");
  }

  const summary = rows[0];

  const areas = await query(
    `
      SELECT aa.name AS upazila_name, district.name AS district_name
      FROM disaster_events de
      INNER JOIN disaster_affected_areas daa ON daa.disaster_event_id = de.id
      INNER JOIN administrative_areas aa ON aa.id = daa.admin_area_id
      LEFT JOIN administrative_areas district ON district.id = aa.parent_area_id
      WHERE de.public_uuid = ?
      ORDER BY district.name, aa.name
    `,
    [publicUuid],
  );

  const shelterAgg = await query(
    `
      SELECT
        COUNT(*) AS active_shelter_count,
        COALESCE(SUM(available_capacity), 0) AS total_available_capacity
      FROM vw_disaster_shelter_capacity
      WHERE disaster_event_id = (
        SELECT id FROM disaster_events WHERE public_uuid = ? LIMIT 1
      )
        AND activation_status = 'active'
    `,
    [publicUuid],
  );

  return {
    ...summary,
    affected_upazilas: areas.rows,
    active_shelter_count: Number(shelterAgg.rows[0]?.active_shelter_count ?? 0),
    total_available_shelter_capacity: Number(
      shelterAgg.rows[0]?.total_available_capacity ?? 0,
    ),
  };
}
