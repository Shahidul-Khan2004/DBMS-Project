import pool, { query } from "../config/db.js";
import BackendError from "../lib/BackendError.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";

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
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const channelId = await findReportChannelId(conn, params.channelCode);
    const categoryId = await findReportCategoryId(conn, params.categoryCode);

    let reportedLocationId = null;
    if (params.location) {
      const normalizedLocation =
        typeof params.location === "string"
          ? {
              admin_area_id: null,
              latitude: 0,
              longitude: 0,
              address_text: params.location,
              place_name: null,
              source: "manual_entry",
            }
          : params.location;

      const [locationResult] = await conn.execute(
        `
          INSERT INTO locations (
            admin_area_id,
            latitude,
            longitude,
            address_text,
            place_name,
            source,
            created_by_user_id
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [
          normalizedLocation.admin_area_id ?? null,
          normalizedLocation.latitude,
          normalizedLocation.longitude,
          normalizedLocation.address_text,
          normalizedLocation.place_name ?? null,
          normalizedLocation.source ?? "user_shared",
          params.reporterUserId ?? null,
        ],
      );
      reportedLocationId = locationResult.insertId;
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
