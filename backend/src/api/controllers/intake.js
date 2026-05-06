import * as intakeService from "../../services/intakeService.js";

export async function createIntakeReport(req, res) {
  const intake = await intakeService.createIntakeReportForUser(req.user.id, req.body);
  res.status(201).json({
    message: "Intake report created",
    intake,
  });
}

export async function getMyIntakeReports(req, res) {
  const reports = await intakeService.listMyIntakeReports(req.user.id);
  res.status(200).json({
    reports,
  });
}

export async function getMyIntakeReportStats(req, res) {
  const stats = await intakeService.getMyIntakeReportStats(req.user.id);
  res.status(200).json({
    stats,
  });
}

export async function classifyServiceCase(req, res) {
  const result = await intakeService.classifyIntakeAsServiceCase(
    req.user.id,
    req.params.reportPublicUuid,
    req.body,
  );
  res.status(201).json({
    message: "Intake classified as service case",
    ...result,
  });
}

export async function classifyEmergency999(req, res) {
  const result = await intakeService.classifyIntakeAsEmergency999(
    req.user.id,
    req.params.reportPublicUuid,
    req.body,
  );
  res.status(201).json({
    message: "Intake classified on emergency (999) path",
    ...result,
  });
}
