import pool from "../config/db.js";
import * as dispatchOperationsRepo from "../repositories/dispatchOperationsRepo.js";
import { resolveReferencePoint } from "../repositories/geoReferenceRepo.js";
import { resolveGeoSortFromQuery } from "./geoSortService.js";

export async function operationsAddAgencyToIncident(actorUserId, incidentPublicUuid, body) {
  const participation = await dispatchOperationsRepo.addAgencyToIncident({
    actorUserId,
    incidentPublicUuid,
    agencyPublicUuid: body.agencyPublicUuid,
    isLeadAgency: Boolean(body.isLeadAgency),
  });
  return { participation };
}

export async function operationsListAvailableUnits(query) {
  let geoSort = null;
  if (query.sort === "distance_asc") {
    const conn = await pool.getConnection();
    try {
      const ref = await resolveReferencePoint(conn, {
        kind: "incident",
        value: query.incidentPublicUuid,
      });
      geoSort = { ref, includeDistance: query.includeDistance === true };
    } finally {
      conn.release();
    }
  }
  return dispatchOperationsRepo.listAvailableUnitsForIncident(query.incidentPublicUuid, {
    geoSort,
  });
}

export async function operationsCreateDispatch(actorUserId, incidentPublicUuid, body) {
  const dispatch = await dispatchOperationsRepo.createDispatch({
    actorUserId,
    incidentPublicUuid,
    unitPublicUuid: body.unitPublicUuid,
    priorityLevel: body.priorityLevel,
    note: body.note,
  });
  return { dispatch };
}

export async function operationsPatchDispatchStatus(actorUserId, dispatchPublicUuid, body) {
  const dispatch = await dispatchOperationsRepo.patchDispatchStatus({
    actorUserId,
    dispatchPublicUuid,
    statusCode: body.statusCode,
    note: body.note,
  });
  return { dispatch };
}

export async function operationsListAgencyWorkload(query = {}) {
  const { geoSort } = await resolveGeoSortFromQuery(query);
  return dispatchOperationsRepo.listAgencyWorkload({ geoSort });
}

export async function operationsGetIncidentResponseTiming(incidentPublicUuid) {
  return dispatchOperationsRepo.getIncidentResponseTiming(incidentPublicUuid);
}
