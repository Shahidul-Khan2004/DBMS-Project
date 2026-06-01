import pool from "../config/db.js";
import { requireAdministrativeAreaInTransaction } from "../domain/locationAccess.js";
import { getLocationRowByPublicUuid, insertLocationInTransaction } from "../repositories/locationRepo.js";
import { findActiveSavedLocationRow } from "../repositories/savedLocationRepo.js";
import { resolveAdminAreaIdForLocationPayload } from "./adminAreaFromGpsService.js";
import { deriveAddressAndSourceForLocation } from "./locationAddressService.js";

/**
 * @param {object | null} row
 * @param {{ adminAreaResolved: boolean, adminAreaMatchedLevel: string | null } | null} [resolutionMeta]
 */
export function mapRowToLocationResponse(row, resolutionMeta = null) {
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

function isOperator(actorPermissions) {
  return (
    actorPermissions.includes("incident.classify") ||
    actorPermissions.includes("incident.create")
  );
}

async function canAccessLocation(conn, actorUserId, actorPermissions, locationRow) {
  const isOwner =
    locationRow.created_by_user_id != null &&
    Number(locationRow.created_by_user_id) === Number(actorUserId);
  if (isOwner || isOperator(actorPermissions)) {
    return true;
  }

  if (actorUserId == null) {
    return false;
  }

  const savedRow = await findActiveSavedLocationRow(conn, actorUserId, locationRow.id);
  return Boolean(savedRow);
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
    const derived = await deriveAddressAndSourceForLocation({
      latitude: body.latitude,
      longitude: body.longitude,
      addressText: body.address_text ?? null,
      source: body.source ?? null,
    });
    const row = await insertLocationInTransaction(conn, {
      admin_area_id: adminToInsert,
      latitude: body.latitude,
      longitude: body.longitude,
      address_text: derived.addressText,
      place_name: body.place_name ?? null,
      source: derived.source ?? body.source,
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

export async function getLocationForActor(publicUuid, actorUserId, actorPermissions = []) {
  const conn = await pool.getConnection();
  try {
    const row = await getLocationRowByPublicUuid(conn, publicUuid);
    if (!row) return null;
    if (!(await canAccessLocation(conn, actorUserId, actorPermissions, row))) return null;
    return mapRowToLocationResponse(row);
  } finally {
    conn.release();
  }
}
