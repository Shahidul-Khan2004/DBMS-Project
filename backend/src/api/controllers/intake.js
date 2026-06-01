import * as intakeService from "../../services/intakeService.js";

export async function createIntakeReport(req, res) {
  const body = req.validated?.body ?? req.body;
  const intake = await intakeService.createIntakeReportForUser(req.user.id, body);
  res.status(201).json({
    message: "Intake report created",
    intake,
  });
}

export async function getMyIntakeReports(req, res) {
  const query = req.validated?.query ?? req.query;
  const reports = await intakeService.listMyIntakeReports(req.user.id, query);
  res.status(200).json({
    reports,
  });
}

export async function getMyIntakeReportByPublicUuid(req, res) {
  const params = req.validated?.params ?? req.params;
  const intake = await intakeService.getMyIntakeReportByPublicUuid(
    req.user.id,
    params.reportPublicUuid,
  );
  res.status(200).json({ report: intake });
}

export async function getMyIntakeReportStats(req, res) {
  const stats = await intakeService.getMyIntakeReportStats(req.user.id);
  res.status(200).json({
    stats,
  });
}

export async function classifyServiceCase(req, res) {
  const body = req.validated?.body ?? req.body;
  const result = await intakeService.classifyIntakeAsServiceCase(
    req.user.id,
    req.params.reportPublicUuid,
    body,
  );
  res.status(201).json({
    message: "Intake classified as service case",
    ...result,
  });
}

export async function classifyEmergency999(req, res) {
  const body = req.validated?.body ?? req.body;
  const result = await intakeService.classifyIntakeAsEmergency999(
    req.user.id,
    req.params.reportPublicUuid,
    body,
  );
  res.status(201).json({
    message: "Intake classified on emergency (999) path",
    ...result,
  });
}

export async function patchMyIntakeReportLocation(req, res) {
  const params = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const report = await intakeService.patchIntakeReportLocation(
    req.user.id,
    req.authz?.roleCodes ?? [],
    params.reportPublicUuid,
    body,
  );
  res.status(200).json({
    message: "Reported location updated",
    report,
  });
}

export async function getMyIntakeReportLocationHistory(req, res) {
  const params = req.validated?.params ?? req.params;
  const history = await intakeService.getIntakeReportLocationHistory(
    req.user.id,
    req.authz?.roleCodes ?? [],
    params.reportPublicUuid,
  );
  res.status(200).json({ history });
}
