import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import {
  assertStatusTransitionAllowed,
  findStatusIdByCode,
} from "../lib/statusWorkflow.js";
import pool from "../config/db.js";
import { buildDistanceSortClause } from "../lib/geoListSql.js";
import { mapRowWithOptionalDistance } from "../lib/geoSortMap.js";

const INCIDENT_MILESTONE_ORDER = [
  "classified",
  "agency_assigned",
  "unit_assigned",
  "dispatched",
  "in_progress",
];

const DISPATCH_COMPLETE_ORDER = ["assigned", "dispatched", "arrived", "completed"];

const TERMINAL_DISPATCH_STATUSES = new Set(["completed", "cancelled"]);

async function loadIncidentByPublicUuid(conn, incidentPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        ei.id AS id,
        ei.public_uuid AS public_uuid,
        ist.status_code AS status_code
      FROM emergency_incidents ei
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [incidentPublicUuid],
  );
  return rows[0] ?? null;
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
  return rows[0] ?? null;
}

async function loadUnitByPublicUuid(conn, unitPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        eu.id AS id,
        eu.public_uuid AS public_uuid,
        eu.agency_id AS agency_id,
        eu.is_active AS is_active,
        us.status_code AS status_code
      FROM emergency_units eu
      INNER JOIN unit_statuses us ON us.id = eu.current_status_id
      WHERE eu.public_uuid = ?
      LIMIT 1
    `,
    [unitPublicUuid],
  );
  return rows[0] ?? null;
}

async function loadDispatchByPublicUuid(conn, dispatchPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        d.id AS id,
        d.public_uuid AS public_uuid,
        d.incident_id AS incident_id,
        d.unit_id AS unit_id,
        eu.agency_id AS agency_id,
        d.priority_level AS priority_level,
        d.assigned_at AS assigned_at,
        d.dispatched_at AS dispatched_at,
        d.arrived_at AS arrived_at,
        d.completed_at AS completed_at,
        d.cancelled_at AS cancelled_at,
        ds.status_code AS status_code,
        ei.public_uuid AS incident_public_uuid,
        eu.public_uuid AS unit_public_uuid
      FROM dispatches d
      INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
      INNER JOIN emergency_incidents ei ON ei.id = d.incident_id
      INNER JOIN emergency_units eu ON eu.id = d.unit_id
      WHERE d.public_uuid = ?
      LIMIT 1
    `,
    [dispatchPublicUuid],
  );
  return rows[0] ?? null;
}

async function loadDispatchStatusCode(conn, dispatchId) {
  const [rows] = await conn.execute(
    `
      SELECT ds.status_code AS status_code
      FROM dispatches d
      INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
      WHERE d.id = ?
      LIMIT 1
    `,
    [dispatchId],
  );
  return rows[0]?.status_code ?? null;
}

async function insertDispatchStatusTransition(conn, dispatchId, toStatusCode, actorUserId, note) {
  const fromCode = await loadDispatchStatusCode(conn, dispatchId);
  if (!fromCode) {
    return;
  }

  const { toStatusId } = await assertStatusTransitionAllowed(
    conn,
    "dispatch",
    fromCode,
    toStatusCode,
    { note: note ?? null },
  );

  await conn.execute(
    `
      INSERT INTO dispatch_status_history (
        dispatch_id,
        status_id,
        changed_by_user_id,
        note
      )
      VALUES (?, ?, ?, ?)
    `,
    [dispatchId, toStatusId, actorUserId ?? null, note ?? null],
  );
}

export async function releaseUnitToAvailable(conn, unitId, actorUserId, note) {
  const [unitRows] = await conn.execute(
    `
      SELECT us.status_code AS status_code
      FROM emergency_units eu
      INNER JOIN unit_statuses us ON us.id = eu.current_status_id
      WHERE eu.id = ?
      LIMIT 1
    `,
    [unitId],
  );
  const unitStatusCode = unitRows[0]?.status_code ?? "busy";
  if (unitStatusCode === "available") {
    return;
  }

  const { toStatusId: availableStatusId } = await assertStatusTransitionAllowed(
    conn,
    "unit",
    unitStatusCode,
    "available",
    { note: null },
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
    [unitId, availableStatusId, actorUserId ?? null, note],
  );
}

export async function tryAdvanceDispatchToward(conn, dispatchId, targetStatusCode, actorUserId, note) {
  let currentCode = await loadDispatchStatusCode(conn, dispatchId);
  if (!currentCode || TERMINAL_DISPATCH_STATUSES.has(currentCode)) {
    return;
  }

  if (targetStatusCode === "cancelled") {
    while (currentCode && !TERMINAL_DISPATCH_STATUSES.has(currentCode)) {
      try {
        await insertDispatchStatusTransition(conn, dispatchId, "cancelled", actorUserId, note);
        currentCode = "cancelled";
      } catch (error) {
        if (error instanceof BackendError && error.code === "INVALID_STATUS_TRANSITION") {
          break;
        }
        throw error;
      }
    }
    return;
  }

  if (targetStatusCode !== "completed") {
    return;
  }

  const targetIndex = DISPATCH_COMPLETE_ORDER.indexOf("completed");
  let currentIndex = DISPATCH_COMPLETE_ORDER.indexOf(currentCode);
  if (currentIndex === -1 || currentIndex >= targetIndex) {
    return;
  }

  while (currentIndex < targetIndex) {
    const nextCode = DISPATCH_COMPLETE_ORDER[currentIndex + 1];
    try {
      await insertDispatchStatusTransition(conn, dispatchId, nextCode, actorUserId, note);
      currentCode = nextCode;
      currentIndex += 1;
    } catch (error) {
      if (error instanceof BackendError && error.code === "INVALID_STATUS_TRANSITION") {
        break;
      }
      throw error;
    }
  }
}

export async function finalizeIncidentDispatches(
  conn,
  incidentId,
  incidentTerminalStatus,
  actorUserId,
) {
  const targetDispatchStatus =
    incidentTerminalStatus === "cancelled" ? "cancelled" : "completed";
  const note = `Incident ${incidentTerminalStatus}`;

  const [rows] = await conn.execute(
    `
      SELECT d.id AS id
      FROM dispatches d
      INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
      WHERE d.incident_id = ?
        AND ds.status_code NOT IN ('completed', 'cancelled')
    `,
    [incidentId],
  );

  for (const row of rows) {
    await tryAdvanceDispatchToward(conn, row.id, targetDispatchStatus, actorUserId, note);
  }
}

export async function releaseIncidentUnits(conn, incidentId, actorUserId, note) {
  const [rows] = await conn.execute(
    `
      SELECT DISTINCT eu.id AS unit_id, us.status_code AS status_code
      FROM dispatches d
      INNER JOIN emergency_units eu ON eu.id = d.unit_id
      INNER JOIN unit_statuses us ON us.id = eu.current_status_id
      WHERE d.incident_id = ?
    `,
    [incidentId],
  );

  for (const row of rows) {
    if (row.status_code === "busy") {
      await releaseUnitToAvailable(conn, row.unit_id, actorUserId, note);
    }
  }
}

export async function tryAdvanceIncidentToward(conn, incidentId, targetStatusCode, actorUserId) {
  const [rows] = await conn.execute(
    `
      SELECT ist.status_code AS status_code
      FROM emergency_incidents ei
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      WHERE ei.id = ?
      LIMIT 1
    `,
    [incidentId],
  );
  if (!rows[0]) {
    return;
  }

  let currentCode = rows[0].status_code;
  const targetIndex = INCIDENT_MILESTONE_ORDER.indexOf(targetStatusCode);
  if (targetIndex === -1) {
    return;
  }

  let currentIndex = INCIDENT_MILESTONE_ORDER.indexOf(currentCode);
  if (currentIndex === -1 || currentIndex >= targetIndex) {
    return;
  }

  while (currentIndex < targetIndex) {
    const nextCode = INCIDENT_MILESTONE_ORDER[currentIndex + 1];
    try {
      const { toStatusId } = await assertStatusTransitionAllowed(
        conn,
        "incident",
        currentCode,
        nextCode,
        { note: null, outcomeId: null },
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
          VALUES (?, ?, NULL, ?, NULL)
        `,
        [incidentId, toStatusId, actorUserId ?? null],
      );
      currentCode = nextCode;
      currentIndex += 1;
    } catch (error) {
      if (error instanceof BackendError && error.code === "INVALID_STATUS_TRANSITION") {
        break;
      }
      throw error;
    }
  }
}

function mapParticipationRow(row) {
  return {
    agency_public_uuid: row.agency_public_uuid,
    agency_name: row.agency_name,
    agency_type_code: row.agency_type_code,
    is_lead_agency: Boolean(row.is_lead_agency),
    participation_status: row.participation_status,
    joined_at: row.joined_at,
  };
}

function mapIncidentDetailDispatchRow(row) {
  return {
    public_uuid: row.public_uuid,
    unit_public_uuid: row.unit_public_uuid,
    status_code: row.status_code,
    priority_level: row.priority_level,
    assigned_at: row.assigned_at,
    dispatched_at: row.dispatched_at,
    arrived_at: row.arrived_at,
    completed_at: row.completed_at,
    cancelled_at: row.cancelled_at,
    unit: {
      public_uuid: row.unit_public_uuid,
      unit_code: row.unit_code,
      unit_name: row.unit_name,
      unit_type_code: row.unit_type_code,
      status_code: row.unit_status_code,
    },
    owning_agency: {
      public_uuid: row.agency_public_uuid,
      agency_name: row.agency_name,
      agency_type_code: row.agency_type_code,
    },
  };
}

export async function listParticipatingAgenciesForIncident(conn, incidentId) {
  const [rows] = await conn.execute(
    `
      SELECT
        a.public_uuid AS agency_public_uuid,
        a.name AS agency_name,
        at.type_code AS agency_type_code,
        iap.is_lead_agency AS is_lead_agency,
        iap.participation_status AS participation_status,
        iap.joined_at AS joined_at
      FROM incident_agency_participation iap
      INNER JOIN agencies a ON a.id = iap.agency_id
      INNER JOIN agency_types at ON at.id = a.agency_type_id
      WHERE iap.incident_id = ?
      ORDER BY iap.is_lead_agency DESC, iap.joined_at ASC
    `,
    [incidentId],
  );
  return rows.map(mapParticipationRow);
}

export async function listDispatchesForIncident(conn, incidentId) {
  const [rows] = await conn.execute(
    `
      SELECT
        d.public_uuid AS public_uuid,
        ds.status_code AS status_code,
        d.priority_level AS priority_level,
        d.assigned_at AS assigned_at,
        d.dispatched_at AS dispatched_at,
        d.arrived_at AS arrived_at,
        d.completed_at AS completed_at,
        d.cancelled_at AS cancelled_at,
        eu.public_uuid AS unit_public_uuid,
        eu.unit_code AS unit_code,
        eu.unit_name AS unit_name,
        eut.type_code AS unit_type_code,
        us.status_code AS unit_status_code,
        a.public_uuid AS agency_public_uuid,
        a.name AS agency_name,
        at.type_code AS agency_type_code
      FROM dispatches d
      INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
      INNER JOIN emergency_units eu ON eu.id = d.unit_id
      INNER JOIN unit_statuses us ON us.id = eu.current_status_id
      INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
      INNER JOIN agencies a ON a.id = eu.agency_id
      INNER JOIN agency_types at ON at.id = a.agency_type_id
      WHERE d.incident_id = ?
      ORDER BY d.assigned_at DESC, d.id DESC
    `,
    [incidentId],
  );
  return rows.map(mapIncidentDetailDispatchRow);
}

function mapDispatchRow(row) {
  return {
    public_uuid: row.public_uuid,
    incident_public_uuid: row.incident_public_uuid,
    unit_public_uuid: row.unit_public_uuid,
    status_code: row.status_code,
    priority_level: row.priority_level,
    assigned_at: row.assigned_at,
    dispatched_at: row.dispatched_at,
    arrived_at: row.arrived_at,
    completed_at: row.completed_at,
    cancelled_at: row.cancelled_at,
  };
}

function mapAvailableUnitRow(row) {
  return {
    public_uuid: row.public_uuid,
    unit_code: row.unit_code,
    unit_name: row.unit_name,
    status_code: row.status_code,
    agency_public_uuid: row.agency_public_uuid,
    agency_name: row.agency_name,
    unit_type_code: row.unit_type_code,
  };
}

export async function addAgencyToIncident(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const incident = await loadIncidentByPublicUuid(conn, params.incidentPublicUuid);
    if (!incident) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }

    const agency = await loadAgencyByPublicUuid(conn, params.agencyPublicUuid);
    if (!agency) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }
    if (!agency.is_active) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    const [existing] = await conn.execute(
      `
        SELECT id
        FROM incident_agency_participation
        WHERE incident_id = ? AND agency_id = ?
        LIMIT 1
      `,
      [incident.id, agency.id],
    );
    if (existing[0]) {
      throw new BackendError(
        409,
        "AGENCY_ALREADY_PARTICIPATING",
        "Agency is already participating on this incident",
      );
    }

    if (params.isLeadAgency) {
      await conn.execute(
        `
          UPDATE incident_agency_participation
          SET is_lead_agency = FALSE
          WHERE incident_id = ?
        `,
        [incident.id],
      );
    }

    await conn.execute(
      `
        INSERT INTO incident_agency_participation (
          incident_id,
          agency_id,
          is_lead_agency,
          participation_status,
          assigned_by_user_id
        )
        VALUES (?, ?, ?, 'active', ?)
      `,
      [
        incident.id,
        agency.id,
        params.isLeadAgency ? 1 : 0,
        params.actorUserId ?? null,
      ],
    );

    await tryAdvanceIncidentToward(conn, incident.id, "agency_assigned", params.actorUserId);

    const [participationRows] = await conn.execute(
      `
        SELECT
          a.public_uuid AS agency_public_uuid,
          a.name AS agency_name,
          at.type_code AS agency_type_code,
          iap.is_lead_agency AS is_lead_agency,
          iap.participation_status AS participation_status,
          iap.joined_at AS joined_at
        FROM incident_agency_participation iap
        INNER JOIN agencies a ON a.id = iap.agency_id
        INNER JOIN agency_types at ON at.id = a.agency_type_id
        WHERE iap.incident_id = ? AND iap.agency_id = ?
        LIMIT 1
      `,
      [incident.id, agency.id],
    );

    await conn.commit();
    return mapParticipationRow(participationRows[0]);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function listAvailableUnitsForIncident(incidentPublicUuid, options = {}) {
  const conn = await pool.getConnection();
  try {
    const incident = await loadIncidentByPublicUuid(conn, incidentPublicUuid);
    if (!incident) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }

    const geoSort = options.geoSort ?? null;
    const useDistance = Boolean(geoSort?.ref);
    const refJoinSql = useDistance
      ? `
        INNER JOIN emergency_incidents ei_ref ON ei_ref.id = ?
        INNER JOIN locations ref_loc ON ref_loc.id = ei_ref.current_location_id
        LEFT JOIN locations entity_loc ON entity_loc.id = eu.base_location_id
      `
      : "";
    const distanceSelect = useDistance
      ? ", ST_Distance_Sphere(ref_loc.geo_point, entity_loc.geo_point) / 1000 AS distance_km_sort"
      : "";
    const orderSql = useDistance
      ? "(entity_loc.id IS NULL), distance_km_sort ASC"
      : "a.name, eu.unit_code";

    const sqlParams = useDistance ? [incident.id, incident.id] : [incident.id];

    const [rows] = await conn.execute(
      `
        SELECT
          eu.public_uuid AS public_uuid,
          eu.unit_code AS unit_code,
          eu.unit_name AS unit_name,
          us.status_code AS status_code,
          a.public_uuid AS agency_public_uuid,
          a.name AS agency_name,
          eut.type_code AS unit_type_code
          ${distanceSelect}
        FROM emergency_units eu
        INNER JOIN unit_statuses us ON us.id = eu.current_status_id
        INNER JOIN agencies a ON a.id = eu.agency_id
        INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
        INNER JOIN incident_agency_participation iap
          ON iap.agency_id = eu.agency_id
         AND iap.incident_id = ?
         AND iap.participation_status IN ('requested', 'active')
        ${refJoinSql}
        WHERE eu.is_active = TRUE
          AND us.status_code = 'available'
        ORDER BY ${orderSql}
      `,
      sqlParams,
    );

    return {
      incident_public_uuid: incident.public_uuid,
      units: rows.map((row) =>
        mapRowWithOptionalDistance(mapAvailableUnitRow(row), row, geoSort),
      ),
    };
  } finally {
    conn.release();
  }
}

export async function createDispatch(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const incident = await loadIncidentByPublicUuid(conn, params.incidentPublicUuid);
    if (!incident) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }

    const unit = await loadUnitByPublicUuid(conn, params.unitPublicUuid);
    if (!unit) {
      throw new BackendError(404, "UNIT_NOT_FOUND", "Unit not found");
    }
    if (!unit.is_active || unit.status_code !== "available") {
      throw new BackendError(409, "UNIT_NOT_AVAILABLE", "Unit is not available for dispatch");
    }

    const [participationRows] = await conn.execute(
      `
        SELECT 1
        FROM incident_agency_participation iap
        WHERE iap.incident_id = ?
          AND iap.agency_id = ?
          AND iap.participation_status IN ('requested', 'active')
        LIMIT 1
      `,
      [incident.id, unit.agency_id],
    );
    if (!participationRows[0]) {
      throw new BackendError(
        409,
        "AGENCY_NOT_PARTICIPATING",
        "Unit agency is not participating on this incident",
      );
    }

    const [existingDispatch] = await conn.execute(
      `
        SELECT id
        FROM dispatches
        WHERE incident_id = ? AND unit_id = ?
        LIMIT 1
      `,
      [incident.id, unit.id],
    );
    if (existingDispatch[0]) {
      throw new BackendError(
        409,
        "DISPATCH_ALREADY_EXISTS",
        "A dispatch already exists for this unit on this incident",
      );
    }

    const assignedStatus = await findStatusIdByCode(conn, "dispatch", "assigned");
    const dispatchPublicUuid = randomUUID();

    const [insertResult] = await conn.execute(
      `
        INSERT INTO dispatches (
          public_uuid,
          incident_id,
          unit_id,
          assigned_by_user_id,
          current_status_id,
          priority_level
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        dispatchPublicUuid,
        incident.id,
        unit.id,
        params.actorUserId,
        assignedStatus.id,
        params.priorityLevel ?? "medium",
      ],
    );

    const dispatchId = insertResult.insertId;

    await conn.execute(
      `
        INSERT INTO dispatch_status_history (
          dispatch_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [dispatchId, assignedStatus.id, params.actorUserId ?? null, params.note ?? null],
    );

    const { toStatusId: busyStatusId } = await assertStatusTransitionAllowed(
      conn,
      "unit",
      unit.status_code,
      "busy",
      { note: null },
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
      [unit.id, busyStatusId, params.actorUserId ?? null, "Dispatched to incident"],
    );

    await tryAdvanceIncidentToward(conn, incident.id, "unit_assigned", params.actorUserId);

    const dispatch = await loadDispatchByPublicUuid(conn, dispatchPublicUuid);
    await conn.commit();
    return mapDispatchRow(dispatch);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function patchDispatchStatus(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const dispatch = await loadDispatchByPublicUuid(conn, params.dispatchPublicUuid);
    if (!dispatch) {
      throw new BackendError(404, "DISPATCH_NOT_FOUND", "Dispatch not found");
    }

    if (params.agencyId != null && Number(dispatch.agency_id) !== Number(params.agencyId)) {
      throw new BackendError(404, "DISPATCH_NOT_FOUND", "Dispatch not found");
    }

    const fromCode = dispatch.status_code;
    const toCode = params.statusCode;

    const { toStatusId } = await assertStatusTransitionAllowed(
      conn,
      "dispatch",
      fromCode,
      toCode,
      { note: params.note ?? null },
    );

    await conn.execute(
      `
        INSERT INTO dispatch_status_history (
          dispatch_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [dispatch.id, toStatusId, params.actorUserId ?? null, params.note ?? null],
    );

    if (toCode === "completed" || toCode === "cancelled") {
      await releaseUnitToAvailable(
        conn,
        dispatch.unit_id,
        params.actorUserId ?? null,
        `Dispatch ${toCode}`,
      );
    }

    if (toCode === "dispatched") {
      await tryAdvanceIncidentToward(conn, dispatch.incident_id, "dispatched", params.actorUserId);
    } else if (toCode === "arrived") {
      await tryAdvanceIncidentToward(conn, dispatch.incident_id, "in_progress", params.actorUserId);
    }

    const updated = await loadDispatchByPublicUuid(conn, params.dispatchPublicUuid);
    await conn.commit();
    return mapDispatchRow(updated);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function listAgencyWorkload(options = {}) {
  const geoSort = options.geoSort ?? null;
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance ? buildDistanceSortClause(geoSort.ref, "entity_loc.id") : null;

  const refJoinSql = useDistance
    ? `
      LEFT JOIN locations entity_loc ON entity_loc.id = a.head_office_location_id
      ${distance.joinSql}
    `
    : "";

  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "a.name";
  const joinParams = useDistance ? distance.joinParams : [];

  const [rows] = await pool.execute(
    `
      SELECT
        a.public_uuid AS agency_public_uuid,
        a.name AS agency_name,
        w.active_incidents AS active_incidents,
        w.total_units AS total_units,
        w.available_units AS available_units,
        w.busy_units AS busy_units,
        w.total_dispatches AS total_dispatches
        ${distanceSelect}
      FROM vw_agency_workload w
      INNER JOIN agencies a ON a.id = w.agency_id
      ${refJoinSql}
      ORDER BY ${orderSql}
    `,
    joinParams,
  );

  const mapRow = (row) => ({
    agency_public_uuid: row.agency_public_uuid,
    agency_name: row.agency_name,
    active_incidents: Number(row.active_incidents),
    total_units: Number(row.total_units),
    available_units: Number(row.available_units),
    busy_units: Number(row.busy_units),
    total_dispatches: Number(row.total_dispatches),
  });

  return {
    agencies: rows.map((row) => mapRowWithOptionalDistance(mapRow(row), row, geoSort)),
  };
}

export async function getIncidentResponseTiming(incidentPublicUuid) {
  const [rows] = await pool.execute(
    `
      SELECT
        ei.public_uuid AS incident_public_uuid,
        ei.incident_code AS incident_code,
        t.first_call_started_at AS first_call_started_at,
        t.incident_created_at AS incident_created_at,
        t.first_agency_joined_at AS first_agency_joined_at,
        t.first_unit_assigned_at AS first_unit_assigned_at,
        t.first_unit_dispatched_at AS first_unit_dispatched_at,
        t.first_unit_arrived_at AS first_unit_arrived_at,
        t.call_to_incident_minutes AS call_to_incident_minutes,
        t.incident_to_agency_minutes AS incident_to_agency_minutes,
        t.agency_to_dispatch_minutes AS agency_to_dispatch_minutes,
        t.dispatch_to_arrival_minutes AS dispatch_to_arrival_minutes
      FROM emergency_incidents ei
      LEFT JOIN vw_response_pipeline_timing t ON t.incident_id = ei.id
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [incidentPublicUuid],
  );

  if (!rows[0]) {
    throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  }

  const row = rows[0];
  return {
    incident_public_uuid: row.incident_public_uuid,
    incident_code: row.incident_code,
    first_call_started_at: row.first_call_started_at,
    incident_created_at: row.incident_created_at,
    first_agency_joined_at: row.first_agency_joined_at,
    first_unit_assigned_at: row.first_unit_assigned_at,
    first_unit_dispatched_at: row.first_unit_dispatched_at,
    first_unit_arrived_at: row.first_unit_arrived_at,
    call_to_incident_minutes: row.call_to_incident_minutes,
    incident_to_agency_minutes: row.incident_to_agency_minutes,
    agency_to_dispatch_minutes: row.agency_to_dispatch_minutes,
    dispatch_to_arrival_minutes: row.dispatch_to_arrival_minutes,
  };
}
