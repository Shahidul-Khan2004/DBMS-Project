import pool from "../config/db.js";
import { getAdministrativeAreaDetailById } from "../repositories/administrativeAreaRepo.js";
import { searchAdministrativeAreas } from "../repositories/administrativeAreaSearchRepo.js";
import BackendError from "../lib/BackendError.js";

export async function searchAdminAreas(params) {
  return searchAdministrativeAreas(params);
}

export async function getAdminAreaById(adminAreaId) {
  const adminArea = await getAdministrativeAreaDetailById(pool, adminAreaId);
  if (!adminArea) {
    throw new BackendError(404, "ADMIN_AREA_NOT_FOUND", "Administrative area not found");
  }
  return adminArea;
}
