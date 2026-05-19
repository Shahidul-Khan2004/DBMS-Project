import * as dispatchOperationsRepo from "../repositories/dispatchOperationsRepo.js";

export async function operationsAddAgencyToIncident(actorUserId, incidentPublicUuid, body) {
  const participation = await dispatchOperationsRepo.addAgencyToIncident({
    actorUserId,
    incidentPublicUuid,
    agencyPublicUuid: body.agencyPublicUuid,
    isLeadAgency: Boolean(body.isLeadAgency),
  });
  return { participation };
}

export async function operationsListAvailableUnits(incidentPublicUuid) {
  return dispatchOperationsRepo.listAvailableUnitsForIncident(incidentPublicUuid);
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

export async function operationsListAgencyWorkload() {
  return dispatchOperationsRepo.listAgencyWorkload();
}

export async function operationsGetIncidentResponseTiming(incidentPublicUuid) {
  return dispatchOperationsRepo.getIncidentResponseTiming(incidentPublicUuid);
}
