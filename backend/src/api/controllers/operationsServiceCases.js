import * as serviceCaseOperationsService from "../../services/serviceCaseOperationsService.js";

export async function listOperationsServiceCases(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await serviceCaseOperationsService.operationsListServiceCases(query);
  res.status(200).json(result);
}

export async function getOperationsServiceCase(req, res) {
  const params = req.validated?.params ?? req.params;
  const result = await serviceCaseOperationsService.operationsGetServiceCase(params.publicUuid);
  res.status(200).json(result);
}

export async function patchOperationsServiceCaseStatus(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const detail = await serviceCaseOperationsService.operationsPatchServiceCaseStatus(
    req.actorUserId,
    params.publicUuid,
    body,
    req,
  );
  res.status(200).json({
    message: "Service case status updated",
    ...detail,
  });
}

export async function postOperationsServiceCaseMessage(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const message = await serviceCaseOperationsService.operationsPostServiceCaseMessage(
    req.actorUserId,
    params.publicUuid,
    body,
    req,
  );
  res.status(201).json({
    message: "Dispatcher response recorded",
    case_message: message,
  });
}

export async function postOperationsServiceCaseAssignment(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await serviceCaseOperationsService.operationsPostServiceCaseAssignment(
    req.actorUserId,
    params.publicUuid,
    body,
    req,
  );
  res.status(201).json({
    message: "Service case assigned",
    assignment: result.assignment,
  });
}

export async function postOperationsServiceCaseResolve(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const detail = await serviceCaseOperationsService.operationsPostServiceCaseResolve(
    req.actorUserId,
    params.publicUuid,
    body,
    req,
  );
  res.status(201).json({
    message: "Service case resolved",
    ...detail,
  });
}
