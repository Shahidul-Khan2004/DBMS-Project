import { randomUUID } from "node:crypto";

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {object} params
 * @param {string} [params.publicUuid]
 * @param {number | null} [params.admin_area_id]
 * @param {number} params.latitude
 * @param {number} params.longitude
 * @param {string} params.address_text
 * @param {string | null} [params.place_name]
 * @param {string} params.source
 * @param {number | null} [params.created_by_user_id]
 * @returns {Promise<object>} inserted row (selected)
 */
export async function insertLocationInTransaction(conn, params) {
  const publicUuid = params.publicUuid ?? randomUUID();
  const lat = Number(params.latitude);
  const lng = Number(params.longitude);
  const trimmed = String(params.address_text ?? "").trim();
  const addressText =
    trimmed.length > 0 ? trimmed : `Coordinates: ${lat}, ${lng}`;

  const [result] = await conn.execute(
    `
      INSERT INTO locations (
        public_uuid,
        admin_area_id,
        latitude,
        longitude,
        address_text,
        place_name,
        source,
        created_by_user_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      publicUuid,
      params.admin_area_id ?? null,
      lat,
      lng,
      addressText,
      params.place_name ?? null,
      params.source,
      params.created_by_user_id ?? null,
    ],
  );

  return getLocationRowById(conn, result.insertId);
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} id
 */
export async function getLocationRowById(conn, id) {
  const [rows] = await conn.execute(
    `
      SELECT
        id,
        public_uuid,
        admin_area_id,
        latitude,
        longitude,
        ST_AsText(geo_point) AS geo_point_wkt,
        address_text,
        place_name,
        source,
        created_by_user_id,
        created_at
      FROM locations
      WHERE id = ?
      LIMIT 1
    `,
    [id],
  );
  return rows[0] || null;
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {string} publicUuid
 */
export async function getLocationRowByPublicUuid(conn, publicUuid) {
  const [rows] = await conn.execute(
    `
      SELECT
        id,
        public_uuid,
        admin_area_id,
        latitude,
        longitude,
        ST_AsText(geo_point) AS geo_point_wkt,
        address_text,
        place_name,
        source,
        created_by_user_id,
        created_at
      FROM locations
      WHERE public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return rows[0] || null;
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} creatorUserId
 */
export async function listLocationRowsByCreatorUserId(conn, creatorUserId) {
  const [rows] = await conn.execute(
    `
      SELECT
        id,
        public_uuid,
        admin_area_id,
        latitude,
        longitude,
        ST_AsText(geo_point) AS geo_point_wkt,
        address_text,
        place_name,
        source,
        created_by_user_id,
        created_at
      FROM locations
      WHERE created_by_user_id = ?
      ORDER BY created_at DESC
    `,
    [creatorUserId],
  );
  return rows;
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} adminAreaId
 * @returns {Promise<{ id: number } | null>}
 */
export async function findAdministrativeAreaById(conn, adminAreaId) {
  const [rows] = await conn.execute(
    `SELECT id FROM administrative_areas WHERE id = ? LIMIT 1`,
    [adminAreaId],
  );
  return rows[0] || null;
}
