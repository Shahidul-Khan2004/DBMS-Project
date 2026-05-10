import pool, { query } from "../config/db.js";
import BackendError from "../lib/BackendError.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
import {
  requireAdministrativeAreaInTransaction,
  requireReporterOwnedLocationId,
} from "../domain/locationAccess.js";
import { resolveAdminAreaIdForLocationPayload } from "../services/adminAreaFromGpsService.js";
import { insertLocationInTransaction } from "./locationRepo.js";

function isDuplicateIntakeIdentityError(error) {
  return (
    error?.code === "ER_DUP_ENTRY" &&
    (error.message.includes("uq_intake_reports_public_uuid") ||
      error.message.includes("uq_intake_reports_report_code"))
  );
}

async function findReportChannelId(conn, channelCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM report_channels
      WHERE channel_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [channelCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "REPORT_CHANNEL_NOT_FOUND", "Invalid or inactive channelCode");
  }
  return rows[0].id;
}

async function findReportCategoryId(conn, categoryCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM report_categories
      WHERE category_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [categoryCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "REPORT_CATEGORY_NOT_FOUND", "Invalid or inactive categoryCode");
  }
  return rows[0].id;
}

/**
 * Intake report persistence. SQL implementation: docs/tickets-intake-gateway-fe-db.md (INTAKE-001).
 *
 * @param {object} params — fields aligned with `intake_reports` + optional related rows (location, reporter_contact, status history)
 * @returns {Promise<{ public_uuid: string, report_code: string, id: bigint }>}
 */
export async function createIntakeReport(params) {
  let gpsResolvedAdminAreaId = null;
  if (params.location && !params.locationId && params.location.admin_area_id == null) {
    const r = await resolveAdminAreaIdForLocationPayload({
      explicitAdminAreaId: null,
      latitude: params.location.latitude,
      longitude: params.location.longitude,
      pool,
    });
    gpsResolvedAdminAreaId = r.adminAreaId;
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const channelId = await findReportChannelId(conn, params.channelCode);
    const categoryId = await findReportCategoryId(conn, params.categoryCode);

    let reportedLocationId = null;
    if (params.locationId) {
      reportedLocationId = await requireReporterOwnedLocationId(
        conn,
        params.locationId,
        params.reporterUserId,
      );
    } else if (params.location) {
      const normalizedLocation = {
        ...params.location,
        source: params.location.source ?? "user_shared",
      };
      const adminAreaIdToUse =
        normalizedLocation.admin_area_id ?? gpsResolvedAdminAreaId ?? null;
      if (adminAreaIdToUse != null) {
        await requireAdministrativeAreaInTransaction(conn, adminAreaIdToUse);
      }
      const inserted = await insertLocationInTransaction(conn, {
        admin_area_id: adminAreaIdToUse,
        latitude: normalizedLocation.latitude,
        longitude: normalizedLocation.longitude,
        address_text: normalizedLocation.address_text,
        place_name: normalizedLocation.place_name ?? null,
        source: normalizedLocation.source,
        created_by_user_id: params.reporterUserId ?? null,
      });
      reportedLocationId = Number(inserted.id);
    }

    const [intakeResult] = await conn.execute(
      `
        INSERT INTO intake_reports (
          public_uuid,
          report_code,
          reporter_user_id,
          reporter_contact_id,
          channel_id,
          category_id,
          reported_location_id,
          urgency_type,
          summary,
          description,
          intake_status,
          received_by_user_id,
          reported_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'received', ?, COALESCE(?, CURRENT_TIMESTAMP))
      `,
      [
        params.publicUuid,
        params.reportCode,
        params.reporterUserId ?? null,
        params.reporterContactId ?? null,
        channelId,
        categoryId,
        reportedLocationId,
        params.urgencyType ?? "unknown",
        params.summary,
        params.description ?? null,
        params.receivedByUserId ?? null,
        toMySqlDateTimeOrNull(params.reportedAt),
      ],
    );

    await conn.execute(
      `
        INSERT INTO intake_report_status_history (
          intake_report_id,
          status,
          changed_by_user_id,
          note
        )
        VALUES (?, 'received', ?, ?)
      `,
      [
        intakeResult.insertId,
        params.receivedByUserId ?? params.reporterUserId ?? null,
        "Initial intake creation",
      ],
    );

    const [rows] = await conn.execute(
      `
        SELECT
          id,
          public_uuid,
          report_code,
          reporter_user_id,
          reporter_contact_id,
          channel_id,
          category_id,
          reported_location_id,
          urgency_type,
          summary,
          description,
          intake_status,
          final_disposition,
          received_by_user_id,
          reported_at,
          created_at,
          updated_at
        FROM intake_reports
        WHERE id = ?
        LIMIT 1
      `,
      [intakeResult.insertId],
    );

    await conn.commit();
    return rows[0];
  } catch (error) {
    await conn.rollback();
    if (isDuplicateIntakeIdentityError(error)) {
      throw new BackendError(409, "INTAKE_IDENTITY_CONFLICT", "Generated intake id/code already exists");
    }
    throw error;
  } finally {
    conn.release();
  }
}

/**
 * Load intake by public UUID for gateway checks and classification.
 *
 * @returns {Promise<object | null>} row shape includes at least: id, public_uuid, intake_status, urgency_type, reporter_user_id, summary, channel_id, category_id, reported_location_id
 */
export async function findIntakeReportByPublicUuid(publicUuid) {
  const result = await query(
    `
      SELECT
        id,
        public_uuid,
        report_code,
        reporter_user_id,
        reporter_contact_id,
        channel_id,
        category_id,
        reported_location_id,
        urgency_type,
        summary,
        description,
        intake_status,
        final_disposition,
        received_by_user_id,
        reported_at,
        created_at,
        updated_at
      FROM intake_reports
      WHERE public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );

  return result.rows[0] || null;
}

export async function listIntakeReportsByReporterUserId(reporterUserId) {
  const result = await query(
    `
      SELECT
        ir.public_uuid,
        ir.report_code,
        ir.summary,
        ir.description,
        ir.urgency_type,
        ir.intake_status,
        ir.final_disposition,
        ir.reported_at,
        ir.created_at,
        rc.channel_code,
        rcat.category_code,
        l.address_text AS location_text
      FROM intake_reports ir
      INNER JOIN report_channels rc ON rc.id = ir.channel_id
      INNER JOIN report_categories rcat ON rcat.id = ir.category_id
      LEFT JOIN locations l ON l.id = ir.reported_location_id
      WHERE ir.reporter_user_id = ?
      ORDER BY ir.created_at DESC
    `,
    [reporterUserId],
  );

  return result.rows;
}

export async function getIntakeReportStatsByReporterUserId(reporterUserId) {
  const result = await query(
    `
      SELECT
        COUNT(*) AS total_reports,
        SUM(
          CASE
            WHEN intake_status IN ('received', 'under_review', 'linked_to_case', 'linked_to_incident')
            THEN 1
            ELSE 0
          END
        ) AS pending_reports,
        SUM(
          CASE
            WHEN intake_status IN ('duplicate', 'false_report', 'closed')
            THEN 1
            ELSE 0
          END
        ) AS resolved_reports
      FROM intake_reports
      WHERE reporter_user_id = ?
    `,
    [reporterUserId],
  );

  const row = result.rows[0] || {};
  return {
    totalReports: Number(row.total_reports || 0),
    pendingReports: Number(row.pending_reports || 0),
    resolvedReports: Number(row.resolved_reports || 0),
  };
}
