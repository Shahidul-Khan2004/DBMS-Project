import pool from "../config/db.js";
import BackendError from "../lib/BackendError.js";
import { getLocationRowByPublicUuid } from "../repositories/locationRepo.js";
import {
  findActiveSavedLocationRow,
  findSavedLocationRow,
  insertSavedLocationInTransaction,
  listActiveSavedLocationRowsForUser,
  restoreSavedLocationInTransaction,
  softDeleteSavedLocationInTransaction,
} from "../repositories/savedLocationRepo.js";
import { mapRowToLocationResponse } from "./locationService.js";

/**
 * Map a joined saved+location row to response shape.
 */
function mapSavedRowToResponse(row) {
  const base = mapRowToLocationResponse(row);
  if (!base) return null;
  return {
    ...base,
    savedLocationPublicUuid: row.saved_location_public_uuid,
    label: row.saved_label ?? null,
    savedAt: row.saved_at,
  };
}

/**
 * Save a location for a user. Idempotent — restores if previously deleted.
 * @param {number} actorUserId
 * @param {string} locationPublicUuid
 * @param {{ label?: string|null }} [opts]
 */
export async function saveLocationForActor(actorUserId, locationPublicUuid, opts = {}) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const locationRow = await getLocationRowByPublicUuid(conn, locationPublicUuid);
    if (!locationRow) {
      throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
    }

    const existing = await findSavedLocationRow(conn, actorUserId, locationRow.id, { forUpdate: true });

    if (existing && !existing.is_deleted) {
      // Already active — return success without duplicate insert
      await conn.commit();
      return { savedLocationPublicUuid: existing.public_uuid, label: existing.label ?? null };
    }

    let savedRow;
    if (existing && existing.is_deleted) {
      savedRow = await restoreSavedLocationInTransaction(conn, existing.id, opts.label ?? null);
    } else {
      savedRow = await insertSavedLocationInTransaction(conn, {
        userId: actorUserId,
        locationId: locationRow.id,
        label: opts.label ?? null,
      });
    }

    await conn.commit();
    return { savedLocationPublicUuid: savedRow.public_uuid, label: savedRow.label ?? null };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

/**
 * Remove (soft-delete) a saved location for a user.
 * @param {number} actorUserId
 * @param {string} locationPublicUuid
 */
export async function unsaveLocationForActor(actorUserId, locationPublicUuid) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const locationRow = await getLocationRowByPublicUuid(conn, locationPublicUuid);
    if (!locationRow) {
      throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
    }

    const savedRow = await findActiveSavedLocationRow(conn, actorUserId, locationRow.id, { forUpdate: true });
    if (!savedRow) {
      throw new BackendError(404, "SAVED_LOCATION_NOT_FOUND", "Saved location not found");
    }

    await softDeleteSavedLocationInTransaction(conn, savedRow.id);
    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

/**
 * List active saved locations for a user.
 * @param {number} actorUserId
 */
export async function listSavedLocationsForActor(actorUserId) {
  const conn = await pool.getConnection();
  try {
    const rows = await listActiveSavedLocationRowsForUser(conn, actorUserId);
    return rows.map(mapSavedRowToResponse);
  } finally {
    conn.release();
  }
}