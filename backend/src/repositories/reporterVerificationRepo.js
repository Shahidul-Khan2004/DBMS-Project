import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import pool, { query } from "../config/db.js";
import { insertAuditLog } from "../lib/auditLog.js";

const VERDICT_VALUES = new Set([
  "genuine",
  "duplicate",
  "mistaken",
  "unverified",
  "false_alarm",
  "malicious_false_report",
]);

export async function resolveIntakeReportIdByPublicUuid(publicUuid) {
  const { rows } = await query(
    `SELECT id, public_uuid, report_code, reporter_user_id, summary
     FROM intake_reports WHERE public_uuid = ? LIMIT 1`,
    [publicUuid],
  );
  return rows[0] ?? null;
}

export async function insertVerificationReview(conn, params) {
  const publicUuid = randomUUID();
  await conn.execute(
    `
      INSERT INTO intake_report_verification_reviews (
        public_uuid,
        intake_report_id,
        reviewed_by_user_id,
        verdict,
        reason,
        evidence_note,
        confidence_level
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      publicUuid,
      params.intakeReportId,
      params.reviewedByUserId,
      params.verdict,
      params.reason ?? null,
      params.evidenceNote ?? null,
      params.confidenceLevel ?? "medium",
    ],
  );

  const [rows] = await conn.execute(
    `
      SELECT
        irvr.public_uuid,
        irvr.verdict,
        irvr.reason,
        irvr.evidence_note,
        irvr.confidence_level,
        irvr.created_at,
        ir.public_uuid AS intake_report_public_uuid,
        ir.report_code,
        ru.public_uuid AS reviewed_by_public_uuid,
        up.full_name AS reviewed_by_full_name
      FROM intake_report_verification_reviews irvr
      INNER JOIN intake_reports ir ON ir.id = irvr.intake_report_id
      INNER JOIN users ru ON ru.id = irvr.reviewed_by_user_id
      LEFT JOIN user_profiles up ON up.user_id = ru.id
      WHERE irvr.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );

  return formatVerificationRow(rows[0]);
}

export async function writeVerificationAuditLog(conn, params) {
  await insertAuditLog(conn, {
    actorUserId: params.actorUserId,
    action: "intake_report.verification_recorded",
    entityType: "intake_report",
    entityId: params.intakeReportId,
    detailsJson: {
      verification_public_uuid: params.verificationPublicUuid,
      verdict: params.verdict,
      confidence_level: params.confidenceLevel,
    },
  });
}

function formatVerificationRow(row) {
  if (!row) return null;
  return {
    public_uuid: row.public_uuid,
    intake_report_public_uuid: row.intake_report_public_uuid,
    report_code: row.report_code,
    verdict: row.verdict,
    reason: row.reason,
    evidence_note: row.evidence_note,
    confidence_level: row.confidence_level,
    created_at: row.created_at,
    reviewed_by: {
      public_uuid: row.reviewed_by_public_uuid,
      full_name: row.reviewed_by_full_name,
    },
  };
}

export async function findLatestVerificationForIntakeReport(intakeReportId) {
  const { rows } = await query(
    `
      SELECT
        irvr.verdict,
        irvr.confidence_level,
        irvr.reason,
        irvr.evidence_note,
        irvr.created_at,
        irvr.public_uuid,
        up.full_name AS reviewed_by_full_name,
        ru.public_uuid AS reviewed_by_public_uuid
      FROM intake_report_verification_reviews irvr
      INNER JOIN users ru ON ru.id = irvr.reviewed_by_user_id
      LEFT JOIN user_profiles up ON up.user_id = ru.id
      WHERE irvr.intake_report_id = ?
      ORDER BY irvr.created_at DESC, irvr.id DESC
      LIMIT 1
    `,
    [intakeReportId],
  );

  const row = rows[0];
  if (!row) return null;

  return {
    public_uuid: row.public_uuid,
    verdict: row.verdict,
    confidence_level: row.confidence_level,
    reason: row.reason,
    evidence_note: row.evidence_note,
    created_at: row.created_at,
    reviewed_by: {
      public_uuid: row.reviewed_by_public_uuid,
      full_name: row.reviewed_by_full_name,
    },
  };
}

export function isValidVerdict(verdict) {
  return VERDICT_VALUES.has(verdict);
}
