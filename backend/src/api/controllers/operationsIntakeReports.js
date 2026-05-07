import * as incidentOperationsService from "../../services/incidentOperationsService.js";

export async function listOperationsIntakeReports(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await incidentOperationsService.operationsListIntakeReports(query);
  res.status(200).json(result);
}

export async function getOperationsIntakeReport(req, res) {
  const params = req.validated?.params ?? req.params;
  const row = await incidentOperationsService.operationsGetIntakeReport(
    params.reportPublicUuid,
  );
  res.status(200).json({ intake_report: row });
}
