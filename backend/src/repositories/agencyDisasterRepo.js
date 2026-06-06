import BackendError from "../lib/BackendError.js";
import pool from "../config/db.js";

const AGENCY_DISASTER_INVOLVEMENT_SQL = `
  EXISTS (
    SELECT 1
    FROM disaster_agency_responsibilities dar
    WHERE dar.disaster_event_id = de.id
      AND dar.agency_id = ?
      AND dar.deactivated_at IS NULL
  )
  OR EXISTS (
    SELECT 1
    FROM shelter_activations sa
    WHERE sa.disaster_event_id = de.id
      AND sa.managing_agency_id = ?
  )
  OR EXISTS (
    SELECT 1
    FROM relief_hub_activations rha
    WHERE rha.disaster_event_id = de.id
      AND rha.managing_agency_id = ?
  )
  OR EXISTS (
    SELECT 1
    FROM relief_requests rr
    WHERE rr.disaster_event_id = de.id
      AND rr.requesting_agency_id = ?
  )
`;

function mapShelterRow(row) {
  return {
    shelter_activation_public_uuid: row.shelter_activation_public_uuid,
    shelter_activation_id: row.shelter_activation_id,
    facility_public_uuid: row.facility_public_uuid,
    facility_name: row.facility_name,
    activation_status: row.activation_status,
    effective_capacity:
      row.effective_capacity != null ? Number(row.effective_capacity) : null,
    latest_occupancy: row.latest_occupancy != null ? Number(row.latest_occupancy) : null,
    available_capacity:
      row.available_capacity != null ? Number(row.available_capacity) : null,
    is_over_capacity: Boolean(row.is_over_capacity),
    managing_agency_public_uuid: row.managing_agency_public_uuid ?? null,
    managing_agency_name: row.managing_agency_name ?? null,
  };
}

function mapReliefHubRow(row) {
  return {
    relief_hub_activation_id: row.relief_hub_activation_id,
    relief_hub_public_uuid: row.relief_hub_public_uuid,
    facility_public_uuid: row.facility_public_uuid,
    facility_name: row.facility_name,
    activation_status: row.activation_status,
    activation_source: row.activation_source,
    managing_agency_public_uuid: row.managing_agency_public_uuid ?? null,
    managing_agency_name: row.managing_agency_name ?? null,
  };
}

function mapReliefShortage(row) {
  const quantityShort = Number(row.shortage_quantity ?? row.quantity_short ?? 0);
  return {
    relief_request_id: row.relief_request_id,
    relief_item_code: row.item_code ?? row.relief_item_code ?? null,
    quantity_requested: row.quantity_requested,
    quantity_delivered: row.total_delivered ?? row.quantity_delivered,
    quantity_short: quantityShort,
  };
}

export async function assertAgencyOwnsReliefHub(
  conn,
  agencyId,
  disasterEventId,
  hubActivationPublicUuid,
) {
  const [rows] = await conn.execute(
    `
      SELECT rha.id
      FROM relief_hub_activations rha
      WHERE rha.public_uuid = ?
        AND rha.disaster_event_id = ?
        AND rha.managing_agency_id = ?
      LIMIT 1
    `,
    [hubActivationPublicUuid, disasterEventId, agencyId],
  );

  if (!rows[0]) {
    throw new BackendError(404, "RELIEF_HUB_NOT_FOUND", "Relief hub activation not found for this agency");
  }

  return rows[0];
}

async function assertAgencyDisasterInvolvement(conn, agencyId, disasterPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT de.id, de.public_uuid
      FROM disaster_events de
      WHERE de.public_uuid = ?
        AND (${AGENCY_DISASTER_INVOLVEMENT_SQL})
      LIMIT 1
    `,
    [disasterPublicUuid, agencyId, agencyId, agencyId, agencyId],
  );

  if (!rows[0]) {
    const [exists] = await conn.execute(
      `SELECT id FROM disaster_events WHERE public_uuid = ? LIMIT 1`,
      [disasterPublicUuid],
    );
    if (!exists[0]) {
      throw new BackendError(404, "DISASTER_NOT_FOUND", "Disaster event not found");
    }
    throw new BackendError(404, "DISASTER_NOT_IN_AGENCY", "Disaster is not assigned to this agency");
  }

  return rows[0];
}

export async function assertAgencyOwnsShelter(
  conn,
  agencyId,
  disasterEventId,
  shelterActivationPublicUuid,
) {
  const [rows] = await conn.execute(
    `
      SELECT sa.id
      FROM shelter_activations sa
      WHERE sa.public_uuid = ?
        AND sa.disaster_event_id = ?
        AND sa.managing_agency_id = ?
      LIMIT 1
    `,
    [shelterActivationPublicUuid, disasterEventId, agencyId],
  );

  if (!rows[0]) {
    throw new BackendError(404, "SHELTER_NOT_FOUND", "Shelter activation not found for this agency");
  }

  return rows[0];
}

export async function listAgencyDisasters(agencyId, { limit = 20, offset = 0 } = {}) {
  const safeLimit = Math.min(Math.max(Number(limit) || 20, 1), 100);
  const safeOffset = Math.max(Number(offset) || 0, 0);

  const [rows] = await pool.execute(
    `
      SELECT
        de.public_uuid AS public_uuid,
        de.event_code AS event_code,
        de.title AS title,
        de.severity_level AS severity_level,
        de.started_at AS started_at,
        de.ended_at AS ended_at,
        des.status_code AS status_code,
        det.type_code AS event_type_code,
        det.name AS event_type_name
      FROM disaster_events de
      INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
      INNER JOIN disaster_event_types det ON det.id = de.event_type_id
      WHERE de.id IN (
        SELECT involved.disaster_event_id
        FROM (
          SELECT dar.disaster_event_id
          FROM disaster_agency_responsibilities dar
          WHERE dar.agency_id = ?
            AND dar.deactivated_at IS NULL
          UNION
          SELECT sa.disaster_event_id
          FROM shelter_activations sa
          WHERE sa.managing_agency_id = ?
          UNION
          SELECT rha.disaster_event_id
          FROM relief_hub_activations rha
          WHERE rha.managing_agency_id = ?
          UNION
          SELECT rr.disaster_event_id
          FROM relief_requests rr
          WHERE rr.requesting_agency_id = ?
        ) involved
      )
      ORDER BY de.started_at DESC, de.id DESC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [agencyId, agencyId, agencyId, agencyId],
  );

  return {
    limit: safeLimit,
    offset: safeOffset,
    disasters: rows,
  };
}

async function loadDisasterBasic(conn, disasterEventId) {
  const [rows] = await conn.execute(
    `
      SELECT
        de.public_uuid,
        de.event_code,
        de.title,
        de.description,
        de.public_guidance,
        de.severity_level,
        de.started_at,
        de.ended_at,
        de.created_at,
        de.updated_at,
        des.status_code,
        det.type_code AS event_type_code,
        det.name AS event_type_name
      FROM disaster_events de
      INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
      INNER JOIN disaster_event_types det ON det.id = de.event_type_id
      WHERE de.id = ?
      LIMIT 1
    `,
    [disasterEventId],
  );
  return rows[0];
}

async function listDeclarations(conn, disasterEventId) {
  const [rows] = await conn.execute(
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
  return rows;
}

async function listAffectedAreas(conn, disasterEventId) {
  const [rows] = await conn.execute(
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
  return rows;
}

export async function listAgencyManagedReliefHubs(agencyId, disasterPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await assertAgencyDisasterInvolvement(conn, agencyId, disasterPublicUuid);

    const [rows] = await conn.execute(
      `
        SELECT
          rha.id AS relief_hub_activation_id,
          rha.public_uuid AS relief_hub_public_uuid,
          rha.activation_status,
          rha.activation_source,
          f.public_uuid AS facility_public_uuid,
          f.name AS facility_name,
          ma.public_uuid AS managing_agency_public_uuid,
          ma.name AS managing_agency_name
        FROM relief_hub_activations rha
        INNER JOIN facilities f ON f.id = rha.facility_id
        LEFT JOIN agencies ma ON ma.id = rha.managing_agency_id
        WHERE rha.disaster_event_id = ?
          AND rha.managing_agency_id = ?
        ORDER BY f.name
      `,
      [disaster.id, agencyId],
    );

    return rows.map(mapReliefHubRow);
  } finally {
    conn.release();
  }
}

async function listAgencyReliefHubInventory(conn, agencyId, disasterEventId) {
  const [rows] = await conn.execute(
    `
      SELECT inv.*
      FROM vw_disaster_relief_inventory_by_hub inv
      INNER JOIN relief_hub_activations rha ON rha.id = inv.relief_hub_activation_id
      WHERE inv.disaster_event_id = ?
        AND rha.managing_agency_id = ?
      ORDER BY inv.facility_name, inv.item_code
    `,
    [disasterEventId, agencyId],
  );
  return rows;
}

export async function listAgencyManagedShelters(agencyId, disasterPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await assertAgencyDisasterInvolvement(conn, agencyId, disasterPublicUuid);

    const [rows] = await conn.execute(
      `
        SELECT v.*
        FROM vw_disaster_shelter_capacity v
        INNER JOIN shelter_activations sa ON sa.id = v.shelter_activation_id
        WHERE v.disaster_event_id = ?
          AND sa.managing_agency_id = ?
        ORDER BY v.facility_name
      `,
      [disaster.id, agencyId],
    );

    return rows.map(mapShelterRow);
  } finally {
    conn.release();
  }
}

async function listAgencyReliefRequestsInTransaction(conn, agencyId, disasterEventId) {
  const [rows] = await conn.execute(
    `
      SELECT
        rr.id AS relief_request_id,
        rr.public_uuid AS relief_request_public_uuid,
        rr.request_code,
        rrs.status_code AS status_code,
        sa.public_uuid AS shelter_activation_public_uuid,
        f.name AS shelter_facility_name,
        rr.request_note,
        rr.created_at
      FROM relief_requests rr
      INNER JOIN relief_request_statuses rrs ON rrs.id = rr.current_status_id
      INNER JOIN shelter_activations sa ON sa.id = rr.shelter_activation_id
      INNER JOIN facilities f ON f.id = sa.facility_id
      WHERE rr.disaster_event_id = ?
        AND (sa.managing_agency_id = ? OR rr.requesting_agency_id = ?)
      ORDER BY rr.created_at DESC
    `,
    [disasterEventId, agencyId, agencyId],
  );

  const requestIds = rows.map((r) => r.relief_request_id);
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

  return rows.map((rr) => ({
    ...rr,
    shortages: shortages
      .filter((s) => s.relief_request_id === rr.relief_request_id)
      .map(mapReliefShortage)
      .filter((s) => s.quantity_short > 0),
  }));
}

export async function listAgencyReliefRequests(agencyId, disasterPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await assertAgencyDisasterInvolvement(conn, agencyId, disasterPublicUuid);
    const reliefRequests = await listAgencyReliefRequestsInTransaction(
      conn,
      agencyId,
      disaster.id,
    );
    return {
      disaster_public_uuid: disaster.public_uuid,
      relief_requests: reliefRequests,
    };
  } finally {
    conn.release();
  }
}

export async function listAgencyDisasterIncidents(agencyId, disasterPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await assertAgencyDisasterInvolvement(conn, agencyId, disasterPublicUuid);

    const [rows] = await conn.execute(
      `
        SELECT
          ei.public_uuid AS incident_public_uuid,
          ei.incident_code,
          ei.title,
          ist.status_code AS incident_status,
          dil.linked_at,
          dil.link_note,
          iap.participation_status
        FROM disaster_incident_links dil
        INNER JOIN emergency_incidents ei ON ei.id = dil.incident_id
        INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
        INNER JOIN incident_agency_participation iap
          ON iap.incident_id = ei.id
         AND iap.agency_id = ?
        WHERE dil.disaster_event_id = ?
          AND dil.unlinked_at IS NULL
          AND iap.participation_status IN ('requested', 'active')
        ORDER BY dil.linked_at DESC
      `,
      [agencyId, disaster.id],
    );

    return {
      disaster_public_uuid: disaster.public_uuid,
      incidents: rows,
    };
  } finally {
    conn.release();
  }
}

export async function getAgencyDisasterDetail(agencyId, disasterPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const disaster = await assertAgencyDisasterInvolvement(conn, agencyId, disasterPublicUuid);
    const basic = await loadDisasterBasic(conn, disaster.id);
    const declarations = await listDeclarations(conn, disaster.id);
    const affectedAreas = await listAffectedAreas(conn, disaster.id);

    const [shelterRows] = await conn.execute(
      `
        SELECT v.*
        FROM vw_disaster_shelter_capacity v
        INNER JOIN shelter_activations sa ON sa.id = v.shelter_activation_id
        WHERE v.disaster_event_id = ?
          AND sa.managing_agency_id = ?
        ORDER BY v.facility_name
      `,
      [disaster.id, agencyId],
    );

    const reliefRequests = await listAgencyReliefRequestsInTransaction(
      conn,
      agencyId,
      disaster.id,
    );

    const [reliefHubRows] = await conn.execute(
      `
        SELECT
          rha.id AS relief_hub_activation_id,
          rha.public_uuid AS relief_hub_public_uuid,
          rha.activation_status,
          rha.activation_source,
          f.public_uuid AS facility_public_uuid,
          f.name AS facility_name,
          ma.public_uuid AS managing_agency_public_uuid,
          ma.name AS managing_agency_name
        FROM relief_hub_activations rha
        INNER JOIN facilities f ON f.id = rha.facility_id
        LEFT JOIN agencies ma ON ma.id = rha.managing_agency_id
        WHERE rha.disaster_event_id = ?
          AND rha.managing_agency_id = ?
        ORDER BY f.name
      `,
      [disaster.id, agencyId],
    );
    const inventoryByHub = await listAgencyReliefHubInventory(conn, agencyId, disaster.id);

    return {
      disaster: {
        public_uuid: basic.public_uuid,
        event_code: basic.event_code,
        title: basic.title,
        description: basic.description,
        public_guidance: basic.public_guidance,
        severity_level: basic.severity_level,
        status_code: basic.status_code,
        event_type_code: basic.event_type_code,
        event_type_name: basic.event_type_name,
        started_at: basic.started_at,
        ended_at: basic.ended_at,
      },
      declarations,
      affected_areas: affectedAreas,
      shelters: shelterRows.map(mapShelterRow),
      relief_hubs: reliefHubRows.map(mapReliefHubRow),
      inventory_by_hub: inventoryByHub,
      relief_requests: reliefRequests,
    };
  } finally {
    conn.release();
  }
}
