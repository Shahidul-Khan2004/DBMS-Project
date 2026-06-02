/**
 * Location reference rules (existence, ownership, FK checks).
 * Uses DB rows via repositories only — no Express middleware here.
 */
import BackendError from "../lib/BackendError.js";
import {
  findAdministrativeAreaById,
  getLocationRowById,
  getLocationRowByPublicUuid,
} from "../repositories/locationRepo.js";

/**
 * Validates `admin_area_id` inside an open transaction (same connection as sibling writes).
 * @param {import("mysql2/promise").PoolConnection} conn
 */
export async function requireAdministrativeAreaInTransaction(conn, adminAreaId) {
  const row = await findAdministrativeAreaById(conn, adminAreaId);
  if (!row) {
    throw new BackendError(422, "ADMIN_AREA_NOT_FOUND", "Invalid admin_area_id");
  }
}

/**
 * Operations / trusted callers: location must exist.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @returns {Promise<number>} internal `locations.id`
 */
export async function requireLocationIdByPublicUuid(conn, locationPublicUuid) {
  const row = await getLocationRowByPublicUuid(conn, locationPublicUuid);
  if (!row) {
    throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
  }
  return Number(row.id);
}

/**
 * Citizen intake: `locations.public_uuid` must exist and be created by the reporter.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @returns {Promise<number>} internal `locations.id`
 */
export async function requireReporterOwnedLocationId(
  conn,
  locationPublicUuid,
  reporterUserId,
) {
  if (reporterUserId == null) {
    throw new BackendError(
      422,
      "LOCATION_ID_REQUIRES_USER",
      "locationId can only be used when the intake has an authenticated reporter",
    );
  }
  const row = await getLocationRowByPublicUuid(conn, locationPublicUuid);
  if (!row) {
    throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
  }
  if (row.created_by_user_id == null || Number(row.created_by_user_id) !== Number(reporterUserId)) {
    throw new BackendError(
      403,
      "LOCATION_NOT_OWNED",
      "You may only reference locations you created",
    );
  }
  return Number(row.id);
}

/**
 * Citizen geo sort: numeric locations.id must exist and belong to the reporter.
 * @param {import("mysql2/promise").PoolConnection} conn
 * @returns {Promise<number>}
 */
export async function requireReporterOwnedLocationById(conn, locationId, reporterUserId) {
  if (reporterUserId == null) {
    throw new BackendError(
      422,
      "LOCATION_ID_REQUIRES_USER",
      "nearLocationId requires an authenticated user",
    );
  }
  const row = await getLocationRowById(conn, locationId);
  if (!row) {
    throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
  }
  if (
    row.created_by_user_id == null ||
    Number(row.created_by_user_id) !== Number(reporterUserId)
  ) {
    throw new BackendError(
      403,
      "LOCATION_NOT_OWNED",
      "You may only reference locations you created",
    );
  }
  return Number(row.id);
}
