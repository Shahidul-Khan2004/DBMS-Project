import * as incidentOperationsService from "../../services/incidentOperationsService.js";

export async function listOperationsIntakeReports(req, res) {
  const result = await incidentOperationsService.operationsListIntakeReports(req.query);
  res.status(200).json(result);
}

export async function getOperationsIntakeReport(req, res) {
  const row = await incidentOperationsService.operationsGetIntakeReport(
    req.params.reportPublicUuid,
  );
  res.status(200).json({ intake_report: row });
}

export async function getOperationsIntakeReportLocationHistory(req, res) {
  const params = req.validated?.params ?? req.params;
  const history = await incidentOperationsService.operationsGetIntakeReportLocationHistory(
    req.actorUserId,
    params.reportPublicUuid,
  );
  res.status(200).json({ history });
}
