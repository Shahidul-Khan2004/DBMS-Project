import * as agencyService from "../../services/agencyService.js";

export async function getAgencyMe(req, res) {
  const result = await agencyService.agencyGetMe(req.actorUserId);
  res.status(200).json(result);
}

export async function getAgencyIncidents(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await agencyService.agencyListIncidents(req.agencyContext.agencyId, query);
  res.status(200).json(result);
}

export async function getAgencyDispatches(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await agencyService.agencyListDispatches(req.agencyContext.agencyId, query);
  res.status(200).json(result);
}

export async function patchAgencyDispatchStatus(req, res) {
  const { dispatchPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const dispatch = await agencyService.agencyPatchDispatchStatus(
    req.agencyContext.agencyId,
    dispatchPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(200).json({ dispatch });
}

export async function getAgencyUnits(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await agencyService.agencyListUnits(req.agencyContext.agencyId, query);
  res.status(200).json(result);
}

export async function postAgencyUnit(req, res) {
  const body = req.validated?.body ?? req.body;
  const unit = await agencyService.agencyCreateUnit(
    req.agencyContext.agencyId,
    body,
    req.actorUserId,
  );
  res.status(201).json({ unit });
}

export async function patchAgencyUnit(req, res) {
  const { unitPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const unit = await agencyService.agencyPatchUnit(
    req.agencyContext.agencyId,
    unitPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(200).json({ unit });
}

export async function patchAgencyDeactivateUnit(req, res) {
  const { unitPublicUuid } = req.validated?.params ?? req.params;
  const unit = await agencyService.agencyDeactivateUnit(
    req.agencyContext.agencyId,
    unitPublicUuid,
  );
  res.status(200).json({
    message: "Unit deactivated",
    unit,
  });
}

export async function patchAgencyUnitStatus(req, res) {
  const { unitPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const unit = await agencyService.agencyPatchUnitStatus(
    req.agencyContext.agencyId,
    unitPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(200).json({ unit });
}

export async function getAgencyResponseLogs(req, res) {
  const { incidentPublicUuid } = req.validated?.params ?? req.params;
  const query = req.validated?.query ?? req.query;
  const result = await agencyService.agencyListResponseLogs(
    req.agencyContext.agencyId,
    incidentPublicUuid,
    query,
  );
  res.status(200).json(result);
}

export async function getAgencyIncidentNotes(req, res) {
  const { incidentPublicUuid } = req.validated?.params ?? req.params;
  const query = req.validated?.query ?? req.query;
  const result = await agencyService.agencyListIncidentNotes(
    req.agencyContext.agencyId,
    incidentPublicUuid,
    query,
  );
  res.status(200).json(result);
}

export async function postAgencyResponseLog(req, res) {
  const { incidentPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const log = await agencyService.agencyCreateResponseLog(
    req.agencyContext.agencyId,
    incidentPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(201).json({ response_log: log });
}

export async function getAgencyDisasters(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await agencyService.agencyListDisasters(
    req.agencyContext.agencyId,
    query,
  );
  res.status(200).json(result);
}

export async function getAgencyDisasterDetail(req, res) {
  const { disasterPublicUuid } = req.validated?.params ?? req.params;
  const result = await agencyService.agencyGetDisasterDetail(
    req.agencyContext.agencyId,
    disasterPublicUuid,
  );
  res.status(200).json(result);
}

export async function getAgencyDisasterShelters(req, res) {
  const { disasterPublicUuid } = req.validated?.params ?? req.params;
  const shelters = await agencyService.agencyListDisasterShelters(
    req.agencyContext.agencyId,
    disasterPublicUuid,
  );
  res.status(200).json({
    disaster_public_uuid: disasterPublicUuid,
    shelters,
  });
}

export async function getAgencyDisasterReliefHubs(req, res) {
  const { disasterPublicUuid } = req.validated?.params ?? req.params;
  const reliefHubs = await agencyService.agencyListDisasterReliefHubs(
    req.agencyContext.agencyId,
    disasterPublicUuid,
  );
  res.status(200).json({
    disaster_public_uuid: disasterPublicUuid,
    relief_hubs: reliefHubs,
  });
}

export async function postAgencyShelterOccupancy(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const snapshot = await agencyService.agencyRecordShelterOccupancy(
    req.agencyContext.agencyId,
    params.disasterPublicUuid,
    params.shelterActivationPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(201).json({ snapshot });
}

export async function getAgencyDisasterReliefRequests(req, res) {
  const { disasterPublicUuid } = req.validated?.params ?? req.params;
  const result = await agencyService.agencyListDisasterReliefRequests(
    req.agencyContext.agencyId,
    disasterPublicUuid,
  );
  res.status(200).json(result);
}

export async function postAgencyDisasterReliefRequest(req, res) {
  const { disasterPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const request = await agencyService.agencyCreateReliefRequest(
    req.agencyContext.agencyId,
    disasterPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(201).json({ request });
}

export async function postAgencyReliefHubStockReceipt(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const receipt = await agencyService.agencyRecordReliefHubStockReceipt(
    req.agencyContext.agencyId,
    params.disasterPublicUuid,
    params.hubActivationPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(201).json({ receipt });
}

export async function getAgencyDisasterIncidents(req, res) {
  const { disasterPublicUuid } = req.validated?.params ?? req.params;
  const result = await agencyService.agencyListDisasterIncidents(
    req.agencyContext.agencyId,
    disasterPublicUuid,
  );
  res.status(200).json(result);
}
