import * as reporterVerificationService from "../../services/reporterVerificationService.js";

export async function postIntakeReportVerification(req, res) {
  const { reportPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await reporterVerificationService.recordIntakeReportVerification(
    reportPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(201).json(result);
}

export async function getIntakeReportReporterRisk(req, res) {
  const { reportPublicUuid } = req.validated?.params ?? req.params;
  const result = await reporterVerificationService.getReporterRiskForIntakeReport(
    reportPublicUuid,
  );
  res.status(200).json(result);
}
