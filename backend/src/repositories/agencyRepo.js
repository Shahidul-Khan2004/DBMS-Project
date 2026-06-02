import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import pool from "../config/db.js";
import { buildDistanceSortClause } from "../lib/geoListSql.js";
import { mapRowWithOptionalDistance } from "../lib/geoSortMap.js";
import {
  assertStatusTransitionAllowed,
  findStatusIdByCode,
} from "../lib/statusWorkflow.js";
import { patchDispatchStatus } from "./dispatchOperationsRepo.js";
import { listIncidentOperatorNotes } from "./incidentOperationsRepo.js";
import { insertLocationInTransaction } from "./locationRepo.js";
import { deriveAddressAndSourceForLocation } from "../services/locationAddressService.js";
import { resolveAdminAreaIdForLocationPayload } from "../services/adminAreaFromGpsService.js";
import { requireAdministrativeAreaInTransaction } from "../domain/locationAccess.js";

export async function loadActiveRepresentativeContext(userId) {
  const [rows] = await pool.execute(
    `
      SELECT
        am.id AS membership_id,
        am.public_uuid AS membership_public_uuid,
        am.membership_role,
        am.membership_status,
        am.joined_at,
        a.id AS agency_id,
        a.public_uuid AS agency_public_uuid,
        a.agency_code,
        a.name AS agency_name,
        a.description AS agency_description,
        a.is_active AS agency_is_active,
        at.type_code AS agency_type_code
      FROM agency_memberships am
      INNER JOIN agencies a ON a.id = am.agency_id
      INNER JOIN agency_types at ON at.id = a.agency_type_id
      WHERE am.user_id = ?
        AND am.membership_role = 'representative'
        AND am.membership_status = 'active'
        AND a.is_active = TRUE
    `,
    [userId],
  );

  if (rows.length === 0) {
    throw new BackendError(403, "MEMBERSHIP_INACTIVE", "No active agency representative membership");
  }
  if (rows.length > 1) {
    throw new BackendError(
      409,
      "MULTIPLE_AGENCY_MEMBERSHIPS",
      "Multiple active representative memberships are not supported",
    );
  }

  return rows[0];
}

export async function getAgencyMeCounts(agencyId) {
  const [rows] = await pool.execute(
    `
      SELECT
        (SELECT COUNT(*) FROM emergency_units eu WHERE eu.agency_id = ?) AS total_units,
        (SELECT COUNT(*) FROM emergency_units eu WHERE eu.agency_id = ? AND eu.is_active = TRUE) AS active_units,
        (
          SELECT COUNT(*)
          FROM dispatches d
          INNER JOIN emergency_units eu ON eu.id = d.unit_id
          INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
          WHERE eu.agency_id = ?
            AND ds.status_code NOT IN ('completed', 'cancelled')
        ) AS open_dispatches,
        (
          SELECT COUNT(DISTINCT iap.incident_id)
          FROM incident_agency_participation iap
          INNER JOIN emergency_incidents ei ON ei.id = iap.incident_id
          INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
          WHERE iap.agency_id = ?
            AND iap.participation_status IN ('requested', 'active')
            AND ist.is_terminal = FALSE
        ) AS active_incidents
    `,
    [agencyId, agencyId, agencyId, agencyId],
  );

  const row = rows[0];
  return {
    total_units: Number(row.total_units),
    active_units: Number(row.active_units),
    open_dispatches: Number(row.open_dispatches),
    active_incidents: Number(row.active_incidents),
  };
}

export function mapAgencyMeResponse(contextRow, counts) {
  return {
    agency: {
      public_uuid: contextRow.agency_public_uuid,
      agency_code: contextRow.agency_code,
      name: contextRow.agency_name,
      description: contextRow.agency_description,
      agency_type_code: contextRow.agency_type_code,
      is_active: Boolean(contextRow.agency_is_active),
    },
    membership: {
      public_uuid: contextRow.membership_public_uuid,
      membership_role: contextRow.membership_role,
      membership_status: contextRow.membership_status,
      joined_at: contextRow.joined_at,
    },
    counts,
  };
}

export async function listAgencyIncidents(agencyId, { limit = 20, offset = 0 }) {
  const safeLimit = Math.min(Math.max(limit, 1), 100);
  const safeOffset = Math.max(offset, 0);

  const [rows] = await pool.execute(
    `
      SELECT
        ei.public_uuid AS incident_public_uuid,
        ei.incident_code,
        ist.status_code,
        iap.participation_status
      FROM incident_agency_participation iap
      INNER JOIN emergency_incidents ei ON ei.id = iap.incident_id
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      WHERE iap.agency_id = ?
      ORDER BY ei.reported_at DESC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [agencyId],
  );

  return {
    limit: safeLimit,
    offset: safeOffset,
    incidents: rows.map((row) => ({
      incident_public_uuid: row.incident_public_uuid,
      incident_code: row.incident_code,
      status_code: row.status_code,
      participation_status: row.participation_status,
    })),
  };
}

export async function listAgencyDispatches(agencyId, { limit = 20, offset = 0 }) {
  const safeLimit = Math.min(Math.max(limit, 1), 100);
  const safeOffset = Math.max(offset, 0);

  const [rows] = await pool.execute(
    `
      SELECT
        d.public_uuid AS dispatch_public_uuid,
        ds.status_code AS status_code,
        d.priority_level,
        d.assigned_at,
        d.dispatched_at,
        d.arrived_at,
        d.completed_at,
        d.cancelled_at,
        ei.public_uuid AS incident_public_uuid,
        ei.incident_code,
        ei.title AS incident_title,
        eu.public_uuid AS unit_public_uuid,
        eu.unit_code,
        eu.unit_name
      FROM dispatches d
      INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
      INNER JOIN emergency_incidents ei ON ei.id = d.incident_id
      INNER JOIN emergency_units eu ON eu.id = d.unit_id
      WHERE eu.agency_id = ?
      ORDER BY d.assigned_at DESC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [agencyId],
  );

  return {
    limit: safeLimit,
    offset: safeOffset,
    dispatches: rows.map((row) => ({
      public_uuid: row.dispatch_public_uuid,
      status_code: row.status_code,
      priority_level: row.priority_level,
      assigned_at: row.assigned_at,
      dispatched_at: row.dispatched_at,
      arrived_at: row.arrived_at,
      completed_at: row.completed_at,
      cancelled_at: row.cancelled_at,
      incident: {
        public_uuid: row.incident_public_uuid,
        incident_code: row.incident_code,
        title: row.incident_title,
      },
      unit: {
        public_uuid: row.unit_public_uuid,
        unit_code: row.unit_code,
        unit_name: row.unit_name,
      },
    })),
  };
}

export async function patchAgencyDispatchStatus(params) {
  return patchDispatchStatus({
    dispatchPublicUuid: params.dispatchPublicUuid,
    statusCode: params.statusCode,
    note: params.note,
    actorUserId: params.actorUserId,
    agencyId: params.agencyId,
  });
}

export async function listAgencyUnits(agencyId, { limit = 50, offset = 0, geoSort = null } = {}) {
  const safeLimit = Math.min(Math.max(limit, 1), 100);
  const safeOffset = Math.max(offset, 0);
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance ? buildDistanceSortClause(geoSort.ref, "entity_loc.id") : null;

  const refJoinSql = useDistance
    ? `
      LEFT JOIN locations entity_loc ON entity_loc.id = eu.base_location_id
      ${distance.joinSql}
    `
    : "";
  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "eu.unit_code";
  const joinParams = useDistance ? distance.joinParams : [];

  const [rows] = await pool.execute(
    `
      SELECT
        eu.public_uuid,
        eu.unit_code,
        eu.unit_name,
        eut.type_code AS unit_type_code,
        us.status_code,
        eu.is_active
        ${distanceSelect}
      FROM emergency_units eu
      INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
      INNER JOIN unit_statuses us ON us.id = eu.current_status_id
      ${refJoinSql}
      WHERE eu.agency_id = ?
      ORDER BY ${orderSql}
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [...joinParams, agencyId],
  );

  const mapUnit = (row) => ({
    public_uuid: row.public_uuid,
    unit_code: row.unit_code,
    unit_name: row.unit_name,
    unit_type_code: row.unit_type_code,
    status_code: row.status_code,
    is_active: Boolean(row.is_active),
  });

  return {
    limit: safeLimit,
    offset: safeOffset,
    units: rows.map((row) => mapRowWithOptionalDistance(mapUnit(row), row, geoSort)),
  };
}

async function insertBaseLocation(conn, locationPayload, actorUserId) {
  let gpsResolvedAdminAreaId = null;
  if (locationPayload.admin_area_id == null) {
    const r = await resolveAdminAreaIdForLocationPayload({
      explicitAdminAreaId: null,
      latitude: locationPayload.latitude,
      longitude: locationPayload.longitude,
      pool,
    });
    gpsResolvedAdminAreaId = r.adminAreaId;
  }
  const derived = await deriveAddressAndSourceForLocation({
    latitude: locationPayload.latitude,
    longitude: locationPayload.longitude,
    addressText: locationPayload.address_text ?? null,
    source: locationPayload.source ?? "manual_entry",
  });
  const adminAreaId = locationPayload.admin_area_id ?? gpsResolvedAdminAreaId ?? null;
  if (adminAreaId != null) {
    await requireAdministrativeAreaInTransaction(conn, adminAreaId);
  }

  const inserted = await insertLocationInTransaction(conn, {
    admin_area_id: adminAreaId,
    latitude: locationPayload.latitude,
    longitude: locationPayload.longitude,
    address_text: derived.addressText,
    place_name: locationPayload.place_name ?? null,
    source: derived.source ?? locationPayload.source ?? "manual_entry",
    created_by_user_id: actorUserId ?? null,
  });
  return Number(inserted.id);
}

export async function createAgencyUnit(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [typeRows] = await conn.execute(
      `SELECT id FROM emergency_unit_types WHERE type_code = ? AND is_active = TRUE LIMIT 1`,
      [params.unitTypeCode],
    );
    if (!typeRows[0]) {
      throw new BackendError(422, "VALIDATION_ERROR", "Invalid unit_type_code");
    }

    const [codeConflict] = await conn.execute(
      `
        SELECT id FROM emergency_units
        WHERE agency_id = ? AND unit_code = ?
        LIMIT 1
      `,
      [params.agencyId, params.unitCode],
    );
    if (codeConflict[0]) {
      throw new BackendError(409, "UNIT_CODE_CONFLICT", "Unit code already exists for this agency");
    }

    const baseLocationId = await insertBaseLocation(conn, params.baseLocation, params.actorUserId);
    const availableStatus = await findStatusIdByCode(conn, "unit", "available");
    const unitPublicUuid = randomUUID();

    const [insertResult] = await conn.execute(
      `
        INSERT INTO emergency_units (
          public_uuid,
          agency_id,
          unit_type_id,
          unit_code,
          unit_name,
          base_location_id,
          current_status_id,
          is_active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, TRUE)
      `,
      [
        unitPublicUuid,
        params.agencyId,
        typeRows[0].id,
        params.unitCode,
        params.unitName,
        baseLocationId,
        availableStatus.id,
      ],
    );

    await conn.execute(
      `
        INSERT INTO unit_status_history (
          unit_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [insertResult.insertId, availableStatus.id, params.actorUserId ?? null, "Unit created"],
    );

    const [unitRow] = await conn.execute(
      `
        SELECT
          eu.public_uuid,
          eu.unit_code,
          eu.unit_name,
          eut.type_code AS unit_type_code,
          us.status_code,
          eu.is_active
        FROM emergency_units eu
        INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
        INNER JOIN unit_statuses us ON us.id = eu.current_status_id
        WHERE eu.public_uuid = ?
        LIMIT 1
      `,
      [unitPublicUuid],
    );

    await conn.commit();
    return {
      public_uuid: unitRow[0].public_uuid,
      unit_code: unitRow[0].unit_code,
      unit_name: unitRow[0].unit_name,
      unit_type_code: unitRow[0].unit_type_code,
      status_code: unitRow[0].status_code,
      is_active: Boolean(unitRow[0].is_active),
    };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function patchAgencyUnit(params) {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.execute(
      `
        SELECT id, agency_id, unit_code, unit_name
        FROM emergency_units
        WHERE public_uuid = ? AND agency_id = ?
        LIMIT 1
      `,
      [params.unitPublicUuid, params.agencyId],
    );
    const unit = rows[0];
    if (!unit) {
      throw new BackendError(404, "UNIT_NOT_FOUND", "Unit not found");
    }

    if (params.unitCode && params.unitCode !== unit.unit_code) {
      const [conflict] = await conn.execute(
        `
          SELECT id FROM emergency_units
          WHERE agency_id = ? AND unit_code = ? AND id <> ?
          LIMIT 1
        `,
        [params.agencyId, params.unitCode, unit.id],
      );
      if (conflict[0]) {
        throw new BackendError(409, "UNIT_CODE_CONFLICT", "Unit code already exists for this agency");
      }
    }

    let baseLocationId = null;
    if (params.baseLocation) {
      baseLocationId = await insertBaseLocation(conn, params.baseLocation, params.actorUserId);
    }

    await conn.execute(
      `
        UPDATE emergency_units
        SET
          unit_code = COALESCE(?, unit_code),
          unit_name = COALESCE(?, unit_name),
          base_location_id = COALESCE(?, base_location_id)
        WHERE id = ?
      `,
      [params.unitCode ?? null, params.unitName ?? null, baseLocationId, unit.id],
    );

    const [updated] = await conn.execute(
      `
        SELECT
          eu.public_uuid,
          eu.unit_code,
          eu.unit_name,
          eut.type_code AS unit_type_code,
          us.status_code,
          eu.is_active
        FROM emergency_units eu
        INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
        INNER JOIN unit_statuses us ON us.id = eu.current_status_id
        WHERE eu.id = ?
        LIMIT 1
      `,
      [unit.id],
    );

    return {
      public_uuid: updated[0].public_uuid,
      unit_code: updated[0].unit_code,
      unit_name: updated[0].unit_name,
      unit_type_code: updated[0].unit_type_code,
      status_code: updated[0].status_code,
      is_active: Boolean(updated[0].is_active),
    };
  } finally {
    conn.release();
  }
}

export async function deactivateAgencyUnit(params) {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.execute(
      `
        SELECT eu.id
        FROM emergency_units eu
        WHERE eu.public_uuid = ? AND eu.agency_id = ?
        LIMIT 1
      `,
      [params.unitPublicUuid, params.agencyId],
    );
    const unit = rows[0];
    if (!unit) {
      throw new BackendError(404, "UNIT_NOT_FOUND", "Unit not found");
    }

    const [openDispatch] = await conn.execute(
      `
        SELECT d.id
        FROM dispatches d
        INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
        WHERE d.unit_id = ?
          AND ds.status_code IN ('assigned', 'dispatched', 'arrived')
        LIMIT 1
      `,
      [unit.id],
    );
    if (openDispatch[0]) {
      throw new BackendError(
        409,
        "UNIT_HAS_ACTIVE_DISPATCH",
        "Cannot deactivate unit with an active or incomplete dispatch",
      );
    }

    await conn.execute(`UPDATE emergency_units SET is_active = FALSE WHERE id = ?`, [unit.id]);

    const [updated] = await conn.execute(
      `
        SELECT
          eu.public_uuid,
          eu.unit_code,
          eu.unit_name,
          eut.type_code AS unit_type_code,
          us.status_code,
          eu.is_active
        FROM emergency_units eu
        INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
        INNER JOIN unit_statuses us ON us.id = eu.current_status_id
        WHERE eu.id = ?
        LIMIT 1
      `,
      [unit.id],
    );

    return {
      public_uuid: updated[0].public_uuid,
      unit_code: updated[0].unit_code,
      unit_name: updated[0].unit_name,
      unit_type_code: updated[0].unit_type_code,
      status_code: updated[0].status_code,
      is_active: Boolean(updated[0].is_active),
    };
  } finally {
    conn.release();
  }
}

export async function patchAgencyUnitStatus(params) {
  const allowed = new Set(["available", "busy"]);
  if (!allowed.has(params.statusCode)) {
    throw new BackendError(
      422,
      "VALIDATION_ERROR",
      "Agency representatives may only set unit status to available or busy",
    );
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute(
      `
        SELECT eu.id, us.status_code
        FROM emergency_units eu
        INNER JOIN unit_statuses us ON us.id = eu.current_status_id
        WHERE eu.public_uuid = ? AND eu.agency_id = ? AND eu.is_active = TRUE
        LIMIT 1
      `,
      [params.unitPublicUuid, params.agencyId],
    );
    const unit = rows[0];
    if (!unit) {
      throw new BackendError(404, "UNIT_NOT_FOUND", "Unit not found");
    }

    const { toStatusId } = await assertStatusTransitionAllowed(
      conn,
      "unit",
      unit.status_code,
      params.statusCode,
      { note: params.note ?? null },
    );

    await conn.execute(
      `
        INSERT INTO unit_status_history (
          unit_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [unit.id, toStatusId, params.actorUserId ?? null, params.note ?? null],
    );

    const [updated] = await conn.execute(
      `
        SELECT
          eu.public_uuid,
          eu.unit_code,
          eu.unit_name,
          eut.type_code AS unit_type_code,
          us.status_code,
          eu.is_active
        FROM emergency_units eu
        INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
        INNER JOIN unit_statuses us ON us.id = eu.current_status_id
        WHERE eu.id = ?
        LIMIT 1
      `,
      [unit.id],
    );

    await conn.commit();
    return {
      public_uuid: updated[0].public_uuid,
      unit_code: updated[0].unit_code,
      unit_name: updated[0].unit_name,
      unit_type_code: updated[0].unit_type_code,
      status_code: updated[0].status_code,
      is_active: Boolean(updated[0].is_active),
    };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function listIncidentNotes(agencyId, incidentPublicUuid, { limit = 20, offset = 0 } = {}) {
  const [incidentRows] = await pool.execute(
    `
      SELECT ei.id
      FROM emergency_incidents ei
      INNER JOIN incident_agency_participation iap
        ON iap.incident_id = ei.id
       AND iap.agency_id = ?
       AND iap.participation_status IN ('requested', 'active')
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [agencyId, incidentPublicUuid],
  );
  if (!incidentRows[0]) {
    throw new BackendError(404, "INCIDENT_NOT_IN_AGENCY", "Incident not found for this agency");
  }

  return listIncidentOperatorNotes(incidentPublicUuid, { limit, offset });
}

export async function listResponseLogs(agencyId, incidentPublicUuid, { limit = 20, offset = 0 }) {
  const safeLimit = Math.min(Math.max(limit, 1), 100);
  const safeOffset = Math.max(offset, 0);

  const [incidentRows] = await pool.execute(
    `
      SELECT ei.id
      FROM emergency_incidents ei
      INNER JOIN incident_agency_participation iap
        ON iap.incident_id = ei.id
       AND iap.agency_id = ?
       AND iap.participation_status IN ('requested', 'active')
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [agencyId, incidentPublicUuid],
  );
  if (!incidentRows[0]) {
    throw new BackendError(404, "INCIDENT_NOT_IN_AGENCY", "Incident not found for this agency");
  }

  const [rows] = await pool.execute(
    `
      SELECT
        rl.id,
        rl.log_type,
        rl.message,
        rl.logged_at,
        d.public_uuid AS dispatch_public_uuid
      FROM response_logs rl
      LEFT JOIN dispatches d ON d.id = rl.dispatch_id
      WHERE rl.incident_id = ?
        AND rl.agency_id = ?
      ORDER BY rl.logged_at DESC, rl.id DESC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [incidentRows[0].id, agencyId],
  );

  return {
    incident_public_uuid: incidentPublicUuid,
    limit: safeLimit,
    offset: safeOffset,
    response_logs: rows.map((row) => ({
      id: Number(row.id),
      log_type: row.log_type,
      message: row.message,
      logged_at: row.logged_at,
      dispatch_public_uuid: row.dispatch_public_uuid ?? null,
    })),
  };
}

export async function createResponseLog(params) {
  const conn = await pool.getConnection();
  try {
    const [incidentRows] = await conn.execute(
      `
        SELECT ei.id
        FROM emergency_incidents ei
        INNER JOIN incident_agency_participation iap
          ON iap.incident_id = ei.id
         AND iap.agency_id = ?
         AND iap.participation_status IN ('requested', 'active')
        WHERE ei.public_uuid = ?
        LIMIT 1
      `,
      [params.agencyId, params.incidentPublicUuid],
    );
    if (!incidentRows[0]) {
      throw new BackendError(404, "INCIDENT_NOT_IN_AGENCY", "Incident not found for this agency");
    }

    let dispatchId = null;
    if (params.dispatchPublicUuid) {
      const [dispatchRows] = await conn.execute(
        `
          SELECT d.id
          FROM dispatches d
          INNER JOIN emergency_units eu ON eu.id = d.unit_id
          WHERE d.public_uuid = ?
            AND d.incident_id = ?
            AND eu.agency_id = ?
          LIMIT 1
        `,
        [params.dispatchPublicUuid, incidentRows[0].id, params.agencyId],
      );
      if (!dispatchRows[0]) {
        throw new BackendError(
          422,
          "RESPONSE_LOG_DISPATCH_MISMATCH",
          "Dispatch does not belong to this agency on this incident",
        );
      }
      dispatchId = dispatchRows[0].id;
    }

    const [insertResult] = await conn.execute(
      `
        INSERT INTO response_logs (
          incident_id,
          dispatch_id,
          agency_id,
          created_by_user_id,
          log_type,
          message
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        incidentRows[0].id,
        dispatchId,
        params.agencyId,
        params.actorUserId ?? null,
        params.logType ?? "update",
        params.message,
      ],
    );

    const [logRow] = await conn.execute(
      `
        SELECT id, log_type, message, logged_at
        FROM response_logs
        WHERE id = ?
        LIMIT 1
      `,
      [insertResult.insertId],
    );

    return {
      id: Number(logRow[0].id),
      log_type: logRow[0].log_type,
      message: logRow[0].message,
      logged_at: logRow[0].logged_at,
      dispatch_public_uuid: params.dispatchPublicUuid ?? null,
    };
  } finally {
    conn.release();
  }
}
