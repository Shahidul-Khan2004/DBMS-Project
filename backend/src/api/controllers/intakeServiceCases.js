import * as serviceCaseOperationsService from "../../services/serviceCaseOperationsService.js";

export async function getMyServiceCases(req, res) {
  const result = await serviceCaseOperationsService.listMyServiceCases(req.user.id);
  res.status(200).json(result);
}

export async function getIntakeServiceCaseMessages(req, res) {
  const params = req.validated?.params ?? req.params;
  const result = await serviceCaseOperationsService.intakeGetServiceCaseMessages(
    req.actorUserId,
    params.publicUuid,
  );
  res.status(200).json(result);
}

export async function postIntakeServiceCaseMessage(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const caseMessage = await serviceCaseOperationsService.intakePostServiceCaseMessage(
    req.actorUserId,
    params.publicUuid,
    body,
    req,
  );
  res.status(201).json({
    message: "Citizen reply recorded",
    case_message: caseMessage,
  });
}

export async function postIntakeReportEscalateToEmergency(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await serviceCaseOperationsService.escalateIntakeFromServiceCase(
    req.actorUserId,
    params.reportPublicUuid,
    body,
    req,
  );
  const { incident_id: _incidentId, ...rest } = result;
  res.status(201).json({
    message: "Service case escalated to emergency incident",
    ...rest,
  });
}
