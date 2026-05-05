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
