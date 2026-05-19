import * as dispatchOperationsService from "../../services/dispatchOperationsService.js";

export async function postOperationsIncidentAgency(req, res) {
  const params = req.validated?.params ?? req.params;
  const { participation } = await dispatchOperationsService.operationsAddAgencyToIncident(
    req.actorUserId,
    params.incidentPublicUuid,
    req.body,
  );
  res.status(201).json({
    message: "Agency added to incident",
    participation,
  });
}

export async function getOperationsAvailableUnits(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await dispatchOperationsService.operationsListAvailableUnits(
    query.incidentPublicUuid,
  );
  res.status(200).json(result);
}

export async function postOperationsIncidentDispatch(req, res) {
  const params = req.validated?.params ?? req.params;
  const { dispatch } = await dispatchOperationsService.operationsCreateDispatch(
    req.actorUserId,
    params.incidentPublicUuid,
    req.body,
  );
  res.status(201).json({
    message: "Dispatch created",
    dispatch,
  });
}

export async function patchOperationsDispatchStatus(req, res) {
  const params = req.validated?.params ?? req.params;
  const { dispatch } = await dispatchOperationsService.operationsPatchDispatchStatus(
    req.actorUserId,
    params.dispatchPublicUuid,
    req.body,
  );
  res.status(200).json({
    message: "Dispatch status updated",
    dispatch,
  });
}

export async function getOperationsAgencyWorkload(req, res) {
  const result = await dispatchOperationsService.operationsListAgencyWorkload();
  res.status(200).json(result);
}

export async function getOperationsIncidentResponseTiming(req, res) {
  const params = req.validated?.params ?? req.params;
  const timing = await dispatchOperationsService.operationsGetIncidentResponseTiming(
    params.incidentPublicUuid,
  );
  res.status(200).json({ timing });
}
