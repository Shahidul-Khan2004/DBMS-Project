import * as incidentOperationsService from "../../services/incidentOperationsService.js";
import * as intakeService from "../../services/intakeService.js";

export async function createOperationsIncident(req, res) {
  const incident = await incidentOperationsService.operationsCreateStandaloneIncident(
    req.actorUserId,
    req.body,
  );
  res.status(201).json({
    message: "Incident created",
    incident,
  });
}

export async function promoteIntakeToEmergency(req, res) {
  const params = req.validated?.params ?? req.params;
  const incident = await incidentOperationsService.operationsPromoteIntakeEmergency(
    req.actorUserId,
    params.reportPublicUuid,
    req.body,
  );
  res.status(201).json({
    message: "Intake promoted to emergency incident",
    incident,
  });
}

export async function listOperationsIncidents(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await incidentOperationsService.operationsListIncidents(query);
  res.status(200).json(result);
}

export async function getOperationsIncident(req, res) {
  const params = req.validated?.params ?? req.params;
  const result = await incidentOperationsService.operationsGetIncident(
    params.incidentPublicUuid,
  );
  res.status(200).json(result);
}

export async function patchOperationsIncidentStatus(req, res) {
  const params = req.validated?.params ?? req.params;
  const incident = await incidentOperationsService.operationsPatchIncidentStatus(
    req.actorUserId,
    params.incidentPublicUuid,
    req.body,
  );
  res.status(200).json({
    message: "Incident status updated",
    incident,
  });
}

export async function postOperationsIncidentNote(req, res) {
  const params = req.validated?.params ?? req.params;
  const note = await incidentOperationsService.operationsAddIncidentNote(
    req.actorUserId,
    params.incidentPublicUuid,
    req.body,
  );
  res.status(201).json({
    message: "Operator note added",
    note,
  });
}

export async function postLinkIntakeReportToIncident(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const link = await incidentOperationsService.operationsLinkIntakeReport(
    req.actorUserId,
    params.incidentPublicUuid,
    body,
  );
  res.status(201).json({
    message: "Intake report linked to incident",
    link,
  });
}

export async function postGateway999IntakeAndIncident(req, res) {
  const body = req.validated?.body ?? req.body;
  const result = await intakeService.createGateway999IntakeAndIncident(
    req.user.id,
    body,
  );
  res.status(201).json({
    message: "999 intake and incident flow completed",
    ...result,
  });
}
