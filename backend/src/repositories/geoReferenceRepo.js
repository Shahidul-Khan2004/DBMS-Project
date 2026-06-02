import BackendError from "../lib/BackendError.js";
import { getLocationRowById } from "./locationRepo.js";

export const NEAR_QUERY_KEYS = [
  "nearIncidentPublicUuid",
  "nearIntakeReportPublicUuid",
  "nearServiceCasePublicUuid",
  "nearDisasterAffectedAreaPublicUuid",
  "nearFacilityPublicUuid",
  "nearLocationId",
];

/**
 * @param {Record<string, unknown>} query
 * @returns {{ kind: string, value: string | number } | null}
 */
export function pickNearReferenceFromQuery(query) {
  if (query.nearLocationId != null) {
    return { kind: "citizen_location", value: Number(query.nearLocationId) };
  }
  if (query.nearIncidentPublicUuid) {
    return { kind: "incident", value: query.nearIncidentPublicUuid };
  }
  if (query.nearIntakeReportPublicUuid) {
    return { kind: "intake", value: query.nearIntakeReportPublicUuid };
  }
  if (query.nearServiceCasePublicUuid) {
    return { kind: "service_case", value: query.nearServiceCasePublicUuid };
  }
  if (query.nearFacilityPublicUuid) {
    return { kind: "facility", value: query.nearFacilityPublicUuid };
  }
  if (query.nearDisasterAffectedAreaPublicUuid) {
    return {
      kind: "disaster_affected_area",
      value: query.nearDisasterAffectedAreaPublicUuid,
    };
  }
  return null;
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} locationId
 */
async function loadReferenceLocation(conn, locationId) {
  const [rows] = await conn.execute(
    `
      SELECT id, latitude, longitude
      FROM locations
      WHERE id = ?
      LIMIT 1
    `,
    [locationId],
  );
  if (!rows[0]) {
    throw new BackendError(404, "LOCATION_NOT_FOUND", "Reference location not found");
  }
  return {
    locationId: Number(rows[0].id),
    latitude: Number(rows[0].latitude),
    longitude: Number(rows[0].longitude),
  };
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {string} incidentPublicUuid
 */
async function resolveIncidentReferenceLocationId(conn, incidentPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT ei.current_location_id AS location_id
      FROM emergency_incidents ei
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [incidentPublicUuid],
  );
  if (!rows[0]) {
    throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  }
  return Number(rows[0].location_id);
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {string} intakePublicUuid
 */
async function resolveIntakeReferenceLocationId(conn, intakePublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT ir.reported_location_id AS location_id
      FROM intake_reports ir
      WHERE ir.public_uuid = ?
      LIMIT 1
    `,
    [intakePublicUuid],
  );
  if (!rows[0]) {
    throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
  }
  return Number(rows[0].location_id);
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {string} casePublicUuid
 */
async function resolveServiceCaseReferenceLocationId(conn, casePublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        sc.current_location_id AS current_location_id,
        ir.reported_location_id AS intake_location_id
      FROM service_cases sc
      LEFT JOIN intake_reports ir ON ir.id = sc.intake_report_id
      WHERE sc.public_uuid = ?
      LIMIT 1
    `,
    [casePublicUuid],
  );
  if (!rows[0]) {
    throw new BackendError(404, "SERVICE_CASE_NOT_FOUND", "Service case not found");
  }
  const locationId = rows[0].current_location_id ?? rows[0].intake_location_id;
  if (locationId == null) {
    throw new BackendError(
      422,
      "GEO_REFERENCE_UNAVAILABLE",
      "Service case has no stored location",
    );
  }
  return Number(locationId);
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {string} facilityPublicUuid
 */
async function resolveFacilityReferenceLocationId(conn, facilityPublicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT f.location_id AS location_id
      FROM facilities f
      WHERE f.public_uuid = ?
      LIMIT 1
    `,
    [facilityPublicUuid],
  );
  if (!rows[0]) {
    throw new BackendError(404, "FACILITY_NOT_FOUND", "Facility not found");
  }
  return Number(rows[0].location_id);
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {string} affectedAreaPublicUuid
 * @param {string | undefined} disasterPublicUuid
 */
async function resolveDisasterAffectedAreaReferenceLocationId(
  conn,
  affectedAreaPublicUuid,
  disasterPublicUuid,
) {
  const [areaRows] = await conn.execute(
    `
      SELECT
        daa.id AS affected_area_id,
        daa.admin_area_id,
        daa.disaster_event_id,
        de.public_uuid AS disaster_public_uuid
      FROM disaster_affected_areas daa
      INNER JOIN disaster_events de ON de.id = daa.disaster_event_id
      WHERE daa.public_uuid = ?
      LIMIT 1
    `,
    [affectedAreaPublicUuid],
  );
  if (!areaRows[0]) {
    throw new BackendError(404, "AFFECTED_AREA_NOT_FOUND", "Disaster affected area not found");
  }
  const area = areaRows[0];
  if (
    disasterPublicUuid != null &&
    area.disaster_public_uuid !== disasterPublicUuid
  ) {
    throw new BackendError(404, "AFFECTED_AREA_NOT_FOUND", "Disaster affected area not found");
  }

  const [locRows] = await conn.execute(
    `
      SELECT l.id AS location_id
      FROM (
        SELECT DISTINCT l.id
        FROM locations l
        INNER JOIN facilities f ON f.location_id = l.id AND f.is_active = TRUE
        INNER JOIN shelter_activations sa ON sa.facility_id = f.id AND sa.disaster_event_id = ?
        WHERE l.admin_area_id = ?
        UNION
        SELECT DISTINCT l.id
        FROM locations l
        INNER JOIN facilities f ON f.location_id = l.id AND f.is_active = TRUE
        INNER JOIN relief_hub_activations rha ON rha.facility_id = f.id AND rha.disaster_event_id = ?
        WHERE l.admin_area_id = ?
        UNION
        SELECT DISTINCT l.id
        FROM locations l
        INNER JOIN emergency_incidents ei ON ei.current_location_id = l.id
        INNER JOIN disaster_incident_links dil
          ON dil.incident_id = ei.id
         AND dil.disaster_event_id = ?
         AND dil.unlinked_at IS NULL
        WHERE l.admin_area_id = ?
      ) picked
      INNER JOIN locations l ON l.id = picked.id
      ORDER BY l.id ASC
      LIMIT 1
    `,
    [
      area.disaster_event_id,
      area.admin_area_id,
      area.disaster_event_id,
      area.admin_area_id,
      area.disaster_event_id,
      area.admin_area_id,
    ],
  );

  if (locRows[0]?.location_id != null) {
    return Number(locRows[0].location_id);
  }

  const [avgRows] = await conn.execute(
    `
      SELECT AVG(l.latitude) AS latitude, AVG(l.longitude) AS longitude
      FROM (
        SELECT DISTINCT l.id, l.latitude, l.longitude
        FROM locations l
        INNER JOIN facilities f ON f.location_id = l.id AND f.is_active = TRUE
        INNER JOIN shelter_activations sa ON sa.facility_id = f.id AND sa.disaster_event_id = ?
        WHERE l.admin_area_id = ?
        UNION
        SELECT DISTINCT l.id, l.latitude, l.longitude
        FROM locations l
        INNER JOIN facilities f ON f.location_id = l.id AND f.is_active = TRUE
        INNER JOIN relief_hub_activations rha ON rha.facility_id = f.id AND rha.disaster_event_id = ?
        WHERE l.admin_area_id = ?
        UNION
        SELECT DISTINCT l.id, l.latitude, l.longitude
        FROM locations l
        INNER JOIN emergency_incidents ei ON ei.current_location_id = l.id
        INNER JOIN disaster_incident_links dil
          ON dil.incident_id = ei.id
         AND dil.disaster_event_id = ?
         AND dil.unlinked_at IS NULL
        WHERE l.admin_area_id = ?
      ) l
    `,
    [
      area.disaster_event_id,
      area.admin_area_id,
      area.disaster_event_id,
      area.admin_area_id,
      area.disaster_event_id,
      area.admin_area_id,
    ],
  );

  const lat = avgRows[0]?.latitude;
  const lng = avgRows[0]?.longitude;
  if (lat == null || lng == null) {
    throw new BackendError(
      422,
      "GEO_REFERENCE_UNAVAILABLE",
      "No geographic anchor for this affected area on the disaster",
    );
  }

  return {
    locationId: null,
    latitude: Number(lat),
    longitude: Number(lng),
  };
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {object} params
 * @param {string} params.kind
 * @param {string | number} params.value
 * @param {string} [params.disasterPublicUuid]
 * @param {number | null} [params.actorUserId]
 */
export async function resolveReferencePoint(conn, params) {
  let locationId;

  switch (params.kind) {
    case "citizen_location": {
      const row = await getLocationRowById(conn, params.value);
      if (!row) {
        throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
      }
      if (
        params.actorUserId != null &&
        (row.created_by_user_id == null ||
          Number(row.created_by_user_id) !== Number(params.actorUserId))
      ) {
        throw new BackendError(
          403,
          "LOCATION_NOT_OWNED",
          "You may only reference locations you created",
        );
      }
      locationId = Number(row.id);
      break;
    }
    case "incident":
      locationId = await resolveIncidentReferenceLocationId(conn, params.value);
      break;
    case "intake":
      locationId = await resolveIntakeReferenceLocationId(conn, params.value);
      break;
    case "service_case":
      locationId = await resolveServiceCaseReferenceLocationId(conn, params.value);
      break;
    case "facility":
      locationId = await resolveFacilityReferenceLocationId(conn, params.value);
      break;
    case "disaster_affected_area": {
      const affectedRef = await resolveDisasterAffectedAreaReferenceLocationId(
        conn,
        params.value,
        params.disasterPublicUuid,
      );
      if (typeof affectedRef === "object" && affectedRef.locationId == null) {
        return affectedRef;
      }
      locationId = affectedRef;
      break;
    }
    default:
      throw new BackendError(422, "VALIDATION_ERROR", "Invalid geo reference kind");
  }

  return loadReferenceLocation(conn, locationId);
}

/**
 * @param {import("mysql2/promise").Pool | import("mysql2/promise").PoolConnection} db
 * @param {Record<string, unknown>} query
 * @param {object} [options]
 * @param {string} [options.disasterPublicUuid]
 * @param {number | null} [options.actorUserId]
 */
export async function resolveReferenceFromQuery(db, query, options = {}) {
  const picked = pickNearReferenceFromQuery(query);
  if (!picked) {
    throw new BackendError(
      422,
      "VALIDATION_ERROR",
      "A near* reference is required for distance sorting",
    );
  }

  const conn =
    typeof db.getConnection === "function" ? await db.getConnection() : db;
  const release = typeof db.getConnection === "function";

  try {
    return await resolveReferencePoint(conn, {
      kind: picked.kind,
      value: picked.value,
      disasterPublicUuid: options.disasterPublicUuid,
      actorUserId: options.actorUserId ?? null,
    });
  } finally {
    if (release) {
      conn.release();
    }
  }
}
