import BackendError from "../../lib/BackendError.js";
import { auditMetaFromRequest } from "../../lib/auditLog.js";
import * as disasterService from "../../services/disasterOperationsService.js";

function audit(req) {
  return auditMetaFromRequest(req);
}

export async function postDisaster(req, res) {
  const body = req.validated?.body ?? req.body;
  const disaster = await disasterService.createDisaster({
    actorUserId: req.actorUserId,
    eventTypeCode: body.eventTypeCode,
    title: body.title,
    description: body.description,
    severityLevel: body.severityLevel,
    startedAt: body.startedAt,
    auditMeta: audit(req),
  });
  res.status(201).json({ disaster });
}

export async function getDisasters(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await disasterService.listDisasters({
    statusCode: query.statusCode,
    limit: query.limit,
    offset: query.offset,
  });
  res.status(200).json(result);
}

export async function getDisaster(req, res) {
  const params = req.validated?.params ?? req.params;
  const query = req.validated?.query ?? req.query;
  const dashboard = await disasterService.getDisasterDashboard(
    params.disasterPublicUuid,
    query,
  );
  if (!dashboard) {
    throw new BackendError(404, "DISASTER_NOT_FOUND", "Disaster not found");
  }
  res.status(200).json(dashboard);
}

export async function patchDisasterStatus(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const disaster = await disasterService.transitionDisasterStatus({
    disasterPublicUuid: params.disasterPublicUuid,
    toStatusCode: body.statusCode,
    note: body.note,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json({ disaster });
}

export async function postAffectedAreas(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await disasterService.addAffectedAreas({
    disasterPublicUuid: params.disasterPublicUuid,
    upazilaAdminAreaIds: body.upazilaAdminAreaIds,
    districtAdminAreaId: body.districtAdminAreaId,
    assessment: body.assessment,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json(result);
}

export async function patchAffectedAreaAssessment(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await disasterService.updateAffectedAreaAssessment({
    disasterPublicUuid: params.disasterPublicUuid,
    affectedAreaPublicUuid: params.affectedAreaPublicUuid,
    assessment: body,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json(result);
}

export async function postResponsibility(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await disasterService.assignResponsibility({
    disasterPublicUuid: params.disasterPublicUuid,
    agencyPublicUuid: body.agencyPublicUuid,
    responsibilityType: body.responsibilityType,
    isLead: body.isLead ?? false,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json(result);
}

export async function postInitialDeclaration(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await disasterService.issueInitialDeclaration({
    disasterPublicUuid: params.disasterPublicUuid,
    title: body.title,
    publicGuidance: body.publicGuidance,
    legalReference: body.legalReference,
    reason: body.reason,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json(result);
}

export async function postDeclarationAmendment(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await disasterService.issueDeclarationAmendment({
    disasterPublicUuid: params.disasterPublicUuid,
    title: body.title,
    publicGuidance: body.publicGuidance,
    legalReference: body.legalReference,
    reason: body.reason,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json(result);
}

export async function getCandidateIncidents(req, res) {
  const params = req.validated?.params ?? req.params;
  const incidents = await disasterService.listCandidateIncidents(params.disasterPublicUuid);
  res.status(200).json({ incidents });
}

export async function getLinkedIncidents(req, res) {
  const params = req.validated?.params ?? req.params;
  const incidents = await disasterService.listLinkedIncidents(params.disasterPublicUuid);
  res.status(200).json({ incidents });
}

export async function postLinkIncident(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const link = await disasterService.linkIncident({
    disasterPublicUuid: params.disasterPublicUuid,
    incidentPublicUuid: body.incidentPublicUuid,
    linkNote: body.linkNote,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json({ link });
}

export async function deleteLinkIncident(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const link = await disasterService.unlinkIncident({
    disasterPublicUuid: params.disasterPublicUuid,
    incidentPublicUuid: params.incidentPublicUuid,
    reason: body.reason,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json({ link });
}

export async function postManualShelter(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const activation = await disasterService.manualActivateShelter({
    disasterPublicUuid: params.disasterPublicUuid,
    facilityPublicUuid: body.facilityPublicUuid,
    usableCapacityOverride: body.usableCapacityOverride,
    manualOverrideNote: body.manualOverrideNote,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json({ activation });
}

export async function postManualReliefHub(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const activation = await disasterService.manualActivateReliefHub({
    disasterPublicUuid: params.disasterPublicUuid,
    facilityPublicUuid: body.facilityPublicUuid,
    manualOverrideNote: body.manualOverrideNote,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json({ activation });
}

export async function postShelterManagingAgency(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const activation = await disasterService.assignShelterManagingAgency({
    shelterActivationPublicUuid: params.shelterActivationPublicUuid,
    agencyPublicUuid: body.agencyPublicUuid,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json({ activation });
}

export async function postShelterOccupancy(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const snapshot = await disasterService.recordShelterOccupancy({
    shelterActivationPublicUuid: params.shelterActivationPublicUuid,
    peopleCount: body.peopleCount,
    actorUserId: req.actorUserId,
    agencyId: req.agencyContext?.agencyId ?? null,
    auditMeta: audit(req),
  });
  res.status(201).json({ snapshot });
}

export async function postDeactivateShelter(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const activation = await disasterService.deactivateShelterActivation({
    disasterPublicUuid: params.disasterPublicUuid,
    shelterActivationPublicUuid: params.shelterActivationPublicUuid,
    note: body.note,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json({ activation });
}

export async function postStockReceipt(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const receipt = await disasterService.recordStockReceipt({
    hubActivationPublicUuid: params.hubActivationPublicUuid,
    reliefItemCode: body.reliefItemCode,
    quantityReceived: body.quantityReceived,
    note: body.note,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json({ receipt });
}

export async function postDeactivateReliefHub(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const activation = await disasterService.deactivateReliefHubActivation({
    disasterPublicUuid: params.disasterPublicUuid,
    hubActivationPublicUuid: params.hubActivationPublicUuid,
    note: body.note,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json({ activation });
}

export async function postReliefRequest(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const request = await disasterService.createReliefRequest({
    disasterPublicUuid: params.disasterPublicUuid,
    shelterActivationPublicUuid: body.shelterActivationPublicUuid,
    items: body.items,
    requestNote: body.requestNote,
    actorUserId: req.actorUserId,
    agencyId: req.agencyContext?.agencyId ?? null,
    auditMeta: audit(req),
  });
  res.status(201).json({ request });
}

export async function postApproveReliefRequest(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const request = await disasterService.approveReliefRequest({
    reliefRequestPublicUuid: params.reliefRequestPublicUuid,
    note: body.note,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json({ request });
}

export async function postRejectReliefRequest(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const request = await disasterService.rejectReliefRequest({
    reliefRequestPublicUuid: params.reliefRequestPublicUuid,
    note: body.note,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(200).json({ request });
}

export async function postReliefDistribution(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const distribution = await disasterService.createReliefDistribution({
    disasterPublicUuid: params.disasterPublicUuid,
    reliefRequestPublicUuid: body.reliefRequestPublicUuid,
    sourceHubActivationPublicUuid: body.sourceHubActivationPublicUuid,
    items: body.items,
    note: body.note,
    actorUserId: req.actorUserId,
    auditMeta: audit(req),
  });
  res.status(201).json({ distribution });
}
