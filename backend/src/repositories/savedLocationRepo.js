import { randomUUID } from "node:crypto";

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} userId
 * @param {number} locationId
 * @returns {Promise<object|null>}
 */
export async function findSavedLocationRow(conn, userId, locationId, { forUpdate = false } = {}) {
  const lock = forUpdate ? " FOR UPDATE" : "";
  const [rows] = await conn.execute(
    `
      SELECT id, public_uuid, user_id, location_id, label, is_deleted, created_at, deleted_at
      FROM saved_locations
      WHERE user_id = ? AND location_id = ?
      LIMIT 1${lock}
    `,
    [userId, locationId],
  );
  return rows[0] || null;
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} userId
 * @param {number} locationId
 * @returns {Promise<object|null>}
 */
export async function findActiveSavedLocationRow(conn, userId, locationId, { forUpdate = false } = {}) {
  const lock = forUpdate ? " FOR UPDATE" : "";
  const [rows] = await conn.execute(
    `
      SELECT id, public_uuid, user_id, location_id, label, is_deleted, created_at, deleted_at
      FROM saved_locations
      WHERE user_id = ? AND location_id = ? AND is_deleted = FALSE
      LIMIT 1${lock}
    `,
    [userId, locationId],
  );
  return rows[0] || null;
}

/**
 * Insert a new saved_locations row.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {{ userId: number, locationId: number, label?: string|null }} params
 * @returns {Promise<object>}
 */
export async function insertSavedLocationInTransaction(conn, params) {
  const publicUuid = randomUUID();
  const label = params.label ?? null;
  await conn.execute(
    `
      INSERT INTO saved_locations (public_uuid, user_id, location_id, label)
      VALUES (?, ?, ?, ?)
    `,
    [publicUuid, params.userId, params.locationId, label],
  );
  const [rows] = await conn.execute(
    `
      SELECT id, public_uuid, user_id, location_id, label, is_deleted, created_at, deleted_at
      FROM saved_locations
      WHERE public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return rows[0];
}

/**
 * Restore a previously soft-deleted saved_locations row.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} savedLocationId
 * @param {string|null} label
 * @returns {Promise<object>}
 */
export async function restoreSavedLocationInTransaction(conn, savedLocationId, label = null) {
  const restoredLabel = label ?? null;
  await conn.execute(
    `
      UPDATE saved_locations
      SET is_deleted = FALSE, deleted_at = NULL, label = ?
      WHERE id = ?
    `,
    [restoredLabel, savedLocationId],
  );
  const [rows] = await conn.execute(
    `
      SELECT id, public_uuid, user_id, location_id, label, is_deleted, created_at, deleted_at
      FROM saved_locations
      WHERE id = ?
      LIMIT 1
    `,
    [savedLocationId],
  );
  return rows[0];
}

/**
 * Soft-delete an active saved_locations row.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} savedLocationId
 */
export async function softDeleteSavedLocationInTransaction(conn, savedLocationId) {
  await conn.execute(
    `
      UPDATE saved_locations
      SET is_deleted = TRUE, deleted_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
    [savedLocationId],
  );
}

/**
 * List all active saved locations for a user, joined with location data.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} userId
 * @param {{ geoSort?: { ref: object, includeDistance: boolean } | null }} [options]
 * @returns {Promise<object[]>}
 */
export async function listActiveSavedLocationRowsForUser(conn, userId, options = {}) {
  const geoSort = options.geoSort ?? null;
  const useDistance = Boolean(geoSort?.ref);

  let refJoinSql = "";
  let joinParams = [];
  let distanceSelect = "";
  let orderSql = "sl.created_at DESC";

  if (useDistance) {
    const { buildReferenceJoin } = await import("../lib/geoListSql.js");
    const { distanceKmSql, orderByDistanceAscSql } = await import("../lib/geoDistance.js");
    const refJoin = buildReferenceJoin(geoSort.ref);
    const refAlias = geoSort.ref.locationId != null ? "ref_loc" : "ref_geom";
    const distanceExpr = distanceKmSql(refAlias, "l");
    refJoinSql = refJoin.joinSql;
    joinParams = refJoin.params;
    distanceSelect = `, ${distanceExpr} AS distance_km_sort`;
    orderSql = orderByDistanceAscSql(distanceExpr, "l.id");
  }

  const [rows] = await conn.execute(
    `
      SELECT
        l.id,
        l.public_uuid,
        l.admin_area_id,
        l.latitude,
        l.longitude,
        ST_AsText(l.geo_point) AS geo_point_wkt,
        l.address_text,
        l.place_name,
        l.source,
        l.created_by_user_id,
        l.created_at,
        sl.public_uuid AS saved_location_public_uuid,
        sl.label       AS saved_label,
        sl.created_at  AS saved_at
        ${distanceSelect}
      FROM saved_locations sl
      JOIN locations l ON l.id = sl.location_id
      ${refJoinSql}
      WHERE sl.user_id = ? AND sl.is_deleted = FALSE
      ORDER BY ${orderSql}
    `,
    [...joinParams, userId],
  );
  return rows;
}