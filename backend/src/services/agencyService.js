import * as agencyRepo from "../repositories/agencyRepo.js";
import * as agencyDisasterRepo from "../repositories/agencyDisasterRepo.js";
import {
  createReliefRequest,
  recordShelterOccupancy,
  recordStockReceipt,
} from "../repositories/disasterOperationsRepo.js";
import { mergeGeoSortIntoFilters, resolveGeoSortFromQuery } from "./geoSortService.js";

export async function resolveAgencyContextForUser(userId) {
  const row = await agencyRepo.loadActiveRepresentativeContext(userId);
  return {
    agencyId: row.agency_id,
    agencyPublicUuid: row.agency_public_uuid,
    membershipPublicUuid: row.membership_public_uuid,
    membershipId: row.membership_id,
  };
}

export async function agencyGetMe(userId) {
  const row = await agencyRepo.loadActiveRepresentativeContext(userId);
  const counts = await agencyRepo.getAgencyMeCounts(row.agency_id);
  return agencyRepo.mapAgencyMeResponse(row, counts);
}

export function agencyListIncidents(agencyId, query) {
  return agencyRepo.listAgencyIncidents(agencyId, query);
}

export function agencyListDispatches(agencyId, query) {
  return agencyRepo.listAgencyDispatches(agencyId, query);
}

export function agencyPatchDispatchStatus(agencyId, dispatchPublicUuid, body, actorUserId) {
  return agencyRepo.patchAgencyDispatchStatus({
    agencyId,
    dispatchPublicUuid,
    statusCode: body.statusCode,
    note: body.note,
    actorUserId,
  });
}

export async function agencyListUnits(agencyId, query) {
  const geo = await resolveGeoSortFromQuery(query);
  return agencyRepo.listAgencyUnits(
    agencyId,
    mergeGeoSortIntoFilters(
      { limit: query.limit, offset: query.offset },
      geo,
    ),
  );
}

export function agencyCreateUnit(agencyId, body, actorUserId) {
  return agencyRepo.createAgencyUnit({
    agencyId,
    unitCode: body.unit_code,
    unitName: body.unit_name,
    unitTypeCode: body.unit_type_code,
    baseLocation: body.base_location,
    actorUserId,
  });
}

export function agencyPatchUnit(agencyId, unitPublicUuid, body, actorUserId) {
  return agencyRepo.patchAgencyUnit({
    agencyId,
    unitPublicUuid,
    unitCode: body.unit_code,
    unitName: body.unit_name,
    baseLocation: body.base_location,
    actorUserId,
  });
}

export function agencyDeactivateUnit(agencyId, unitPublicUuid) {
  return agencyRepo.deactivateAgencyUnit({ agencyId, unitPublicUuid });
}

export function agencyPatchUnitStatus(agencyId, unitPublicUuid, body, actorUserId) {
  return agencyRepo.patchAgencyUnitStatus({
    agencyId,
    unitPublicUuid,
    statusCode: body.status_code,
    note: body.note,
    actorUserId,
  });
}

export function agencyListResponseLogs(agencyId, incidentPublicUuid, query) {
  return agencyRepo.listResponseLogs(agencyId, incidentPublicUuid, query);
}

export function agencyListIncidentNotes(agencyId, incidentPublicUuid, query) {
  return agencyRepo.listIncidentNotes(agencyId, incidentPublicUuid, query);
}

export function agencyCreateResponseLog(agencyId, incidentPublicUuid, body, actorUserId) {
  return agencyRepo.createResponseLog({
    agencyId,
    incidentPublicUuid,
    dispatchPublicUuid: body.dispatch_public_uuid,
    logType: body.log_type,
    message: body.message,
    actorUserId,
  });
}

export function agencyListDisasters(agencyId, query) {
  return agencyDisasterRepo.listAgencyDisasters(agencyId, query);
}

export function agencyGetDisasterDetail(agencyId, disasterPublicUuid) {
  return agencyDisasterRepo.getAgencyDisasterDetail(agencyId, disasterPublicUuid);
}

export function agencyListDisasterShelters(agencyId, disasterPublicUuid) {
  return agencyDisasterRepo.listAgencyManagedShelters(agencyId, disasterPublicUuid);
}

export function agencyListDisasterReliefHubs(agencyId, disasterPublicUuid) {
  return agencyDisasterRepo.listAgencyManagedReliefHubs(agencyId, disasterPublicUuid);
}

export function agencyListDisasterReliefRequests(agencyId, disasterPublicUuid) {
  return agencyDisasterRepo.listAgencyReliefRequests(agencyId, disasterPublicUuid);
}

export function agencyListDisasterIncidents(agencyId, disasterPublicUuid) {
  return agencyDisasterRepo.listAgencyDisasterIncidents(agencyId, disasterPublicUuid);
}

export function agencyRecordShelterOccupancy(
  agencyId,
  disasterPublicUuid,
  shelterActivationPublicUuid,
  body,
  actorUserId,
) {
  return recordShelterOccupancy({
    disasterPublicUuid,
    shelterActivationPublicUuid,
    peopleCount: body.peopleCount,
    agencyId,
    actorUserId,
  });
}

export function agencyCreateReliefRequest(
  agencyId,
  disasterPublicUuid,
  body,
  actorUserId,
) {
  return createReliefRequest({
    disasterPublicUuid,
    shelterActivationPublicUuid: body.shelterActivationPublicUuid,
    items: body.items,
    requestNote: body.requestNote,
    agencyId,
    actorUserId,
  });
}

export function agencyRecordReliefHubStockReceipt(
  agencyId,
  disasterPublicUuid,
  hubActivationPublicUuid,
  body,
  actorUserId,
) {
  return recordStockReceipt({
    disasterPublicUuid,
    reliefHubActivationPublicUuid: hubActivationPublicUuid,
    reliefItemCode: body.reliefItemCode,
    quantityReceived: body.quantityReceived,
    note: body.note,
    agencyId,
    actorUserId,
  });
}
