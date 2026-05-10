import pool from "../config/db.js";
import { requireAdministrativeAreaInTransaction } from "../domain/locationAccess.js";
import { insertLocationInTransaction } from "../repositories/locationRepo.js";
import { resolveAdminAreaIdForLocationPayload } from "./adminAreaFromGpsService.js";

/**
 * @param {object | null} row
 * @param {{ adminAreaResolved: boolean, adminAreaMatchedLevel: string | null } | null} [resolutionMeta]
 */
function mapRowToLocationResponse(row, resolutionMeta = null) {
  if (!row) return null;
  const base = {
    id: Number(row.id),
    publicUuid: row.public_uuid,
    adminAreaId: row.admin_area_id != null ? Number(row.admin_area_id) : null,
    latitude: Number(row.latitude),
    longitude: Number(row.longitude),
    geoPointWkt: row.geo_point_wkt,
    addressText: row.address_text,
    placeName: row.place_name,
    source: row.source,
    createdByUserId:
      row.created_by_user_id != null ? Number(row.created_by_user_id) : null,
    createdAt: row.created_at,
  };
  if (resolutionMeta) {
    base.adminAreaResolved = resolutionMeta.adminAreaResolved;
    base.adminAreaMatchedLevel = resolutionMeta.adminAreaMatchedLevel;
  }
  return base;
}

/**
 * @param {number | null} actorUserId — internal users.id
 * @param {object} body — validated create location body
 */
export async function createLocationForActor(actorUserId, body) {
  let resolutionMeta = {
    adminAreaResolved: false,
    adminAreaMatchedLevel: null,
  };
  let adminToInsert = body.admin_area_id ?? null;
  if (body.admin_area_id == null) {
    const r = await resolveAdminAreaIdForLocationPayload({
      explicitAdminAreaId: null,
      latitude: body.latitude,
      longitude: body.longitude,
      pool,
    });
    adminToInsert = r.adminAreaId;
    resolutionMeta = r.resolutionMeta;
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    if (adminToInsert != null) {
      await requireAdministrativeAreaInTransaction(conn, adminToInsert);
    }
    const row = await insertLocationInTransaction(conn, {
      admin_area_id: adminToInsert,
      latitude: body.latitude,
      longitude: body.longitude,
      address_text: body.address_text,
      place_name: body.place_name ?? null,
      source: body.source,
      created_by_user_id: actorUserId,
    });
    await conn.commit();
    return mapRowToLocationResponse(row, resolutionMeta);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}
