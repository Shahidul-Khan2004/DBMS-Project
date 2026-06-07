import pool from "../config/db.js";
import BackendError from "../lib/BackendError.js";
import {
  findLatestVerificationForIntakeReport,
  insertVerificationReview,
  resolveIntakeReportIdByPublicUuid,
  writeVerificationAuditLog,
} from "../repositories/reporterVerificationRepo.js";
import {
  findReporterRiskByUserId,
  listRecentVerificationsForReporter,
} from "../repositories/reporterRiskRepo.js";

export async function recordIntakeReportVerification(
  reportPublicUuid,
  body,
  actorUserId,
) {
  const report = await resolveIntakeReportIdByPublicUuid(reportPublicUuid);
  if (!report) {
    throw new BackendError(
      404,
      "INTAKE_REPORT_NOT_FOUND",
      "Intake report not found",
    );
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const verification = await insertVerificationReview(conn, {
      intakeReportId: report.id,
      reviewedByUserId: actorUserId,
      verdict: body.verdict,
      reason: body.reason,
      evidenceNote: body.evidenceNote,
      confidenceLevel: body.confidenceLevel ?? "medium",
    });

    await writeVerificationAuditLog(conn, {
      actorUserId,
      intakeReportId: report.id,
      verificationPublicUuid: verification.public_uuid,
      verdict: body.verdict,
      confidenceLevel: body.confidenceLevel ?? "medium",
    });

    await conn.commit();

    const reporterRisk = report.reporter_user_id
      ? await findReporterRiskByUserId(report.reporter_user_id, { compact: true })
      : null;

    return {
      message: "Intake report verification recorded",
      verification,
      reporter_risk: reporterRisk,
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

export async function getReporterRiskForIntakeReport(reportPublicUuid) {
  const report = await resolveIntakeReportIdByPublicUuid(reportPublicUuid);
  if (!report) {
    throw new BackendError(
      404,
      "INTAKE_REPORT_NOT_FOUND",
      "Intake report not found",
    );
  }

  if (!report.reporter_user_id) {
    return { reporter_risk: null, recent_verifications: [] };
  }

  const [reporterRisk, recentVerifications] = await Promise.all([
    findReporterRiskByUserId(report.reporter_user_id),
    listRecentVerificationsForReporter(report.reporter_user_id),
  ]);

  return {
    reporter_risk: reporterRisk,
    recent_verifications: recentVerifications,
  };
}

export async function getLatestVerificationAndReporterRisk(intakeReportId, reporterUserId) {
  const [latestVerification, reporterRisk] = await Promise.all([
    findLatestVerificationForIntakeReport(intakeReportId),
    reporterUserId
      ? findReporterRiskByUserId(reporterUserId, { compact: true })
      : Promise.resolve(null),
  ]);

  return {
    latest_verification: latestVerification
      ? {
          verdict: latestVerification.verdict,
          confidence_level: latestVerification.confidence_level,
          reason: latestVerification.reason,
          created_at: latestVerification.created_at,
        }
      : null,
    reporter_risk: reporterRisk,
  };
}
