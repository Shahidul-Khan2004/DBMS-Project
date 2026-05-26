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
