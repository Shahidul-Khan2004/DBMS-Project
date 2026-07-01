import pool, { query } from "../config/db.js";
import BackendError from "../lib/BackendError.js";
import { buildDistanceSortClause } from "../lib/geoListSql.js";
import { mapRowWithOptionalDistance } from "../lib/geoSortMap.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
import {
  requireAdministrativeAreaInTransaction,
  requireLocationIdByPublicUuid,
  requireReporterOwnedLocationId,
} from "../domain/locationAccess.js";
import { ROLE_CODES } from "../services/rbacService.js";
import { resolveAdminAreaIdForLocationPayload } from "../services/adminAreaFromGpsService.js";
import { deriveAddressAndSourceForLocation } from "../services/locationAddressService.js";
import { insertLocationInTransaction } from "./locationRepo.js";
import { findStatusIdByCode } from "../lib/statusWorkflow.js";

function isDuplicateIntakeIdentityError(error) {
  const pgDup =
    error?.code === "23505" &&
    (error.constraint?.includes("uq_intake_reports") ||
      error.message?.includes("uq_intake_reports"));
  return (
    pgDup ||
    (error?.code === "ER_DUP_ENTRY" &&
      (error.message.includes("uq_intake_reports_public_uuid") ||
        error.message.includes("uq_intake_reports_report_code")))
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

function mapLocationFromRow(row) {
  if (row.location_public_uuid == null) return null;
  return {
    public_uuid: row.location_public_uuid,
    latitude: Number(row.location_latitude),
    longitude: Number(row.location_longitude),
    address_text: row.location_address_text,
    place_name: row.location_place_name ?? null,
    admin_area_id:
      row.location_admin_area_id != null ? Number(row.location_admin_area_id) : null,
    source: row.location_source ?? null,
  };
}

function mapIntakeReportCore(row) {
  return {
    public_uuid: row.public_uuid,
    report_code: row.report_code,
    summary: row.summary,
    description: row.description,
    intake_status: row.intake_status,
    final_disposition: row.final_disposition,
    reported_at: row.reported_at,
    created_at: row.created_at,
    channel_code: row.channel_code,
    category_code: row.category_code,
    location: mapLocationFromRow(row),
  };
}

function mapIntakeReportWithLocation(row) {
  return {
    ...mapIntakeReportCore(row),
    location_text: row.location_address_text ?? null,
  };
}

async function insertIntakeLocationHistoryInTransaction(conn, params) {
  await conn.execute(
    `
      INSERT INTO intake_report_location_history (
        intake_report_id,
        location_id,
        previous_location_id,
        change_kind,
        changed_by_user_id,
        change_reason
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    [
      params.intakeReportId,
      params.locationId,
      params.previousLocationId ?? null,
      params.changeKind,
      params.changedByUserId ?? null,
      params.changeReason ?? null,
    ],
  );
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
      const derivedAddress = await deriveAddressAndSourceForLocation({
        latitude: normalizedLocation.latitude,
        longitude: normalizedLocation.longitude,
        addressText: normalizedLocation.address_text ?? null,
        source: normalizedLocation.source ?? null,
      });
      const adminAreaIdToUse =
        normalizedLocation.admin_area_id ?? gpsResolvedAdminAreaId ?? null;
      if (adminAreaIdToUse != null) {
        await requireAdministrativeAreaInTransaction(conn, adminAreaIdToUse);
      }
      const inserted = await insertLocationInTransaction(conn, {
        admin_area_id: adminAreaIdToUse,
        latitude: normalizedLocation.latitude,
        longitude: normalizedLocation.longitude,
        address_text: derivedAddress.addressText,
        place_name: normalizedLocation.place_name ?? null,
        source: derivedAddress.source ?? normalizedLocation.source,
        created_by_user_id: params.reporterUserId ?? null,
      });
      reportedLocationId = Number(inserted.id);
    }

    const { id: receivedStatusId } = await findStatusIdByCode(conn, "intake", "received");

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
          summary,
          description,
          current_status_id,
          received_by_user_id,
          reported_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
      `,
      [
        params.publicUuid,
        params.reportCode,
        params.reporterUserId ?? null,
        params.reporterContactId ?? null,
        channelId,
        categoryId,
        reportedLocationId,
        params.summary,
        params.description ?? null,
        receivedStatusId,
        params.receivedByUserId ?? null,
        toMySqlDateTimeOrNull(params.reportedAt),
      ],
    );

    await conn.execute(
      `
        INSERT INTO intake_report_status_history (
          intake_report_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [
        intakeResult.insertId,
        receivedStatusId,
        params.receivedByUserId ?? params.reporterUserId ?? null,
        "Initial intake creation",
      ],
    );

    if (reportedLocationId != null) {
      await insertIntakeLocationHistoryInTransaction(conn, {
        intakeReportId: intakeResult.insertId,
        locationId: reportedLocationId,
        previousLocationId: null,
        changeKind: "initial_create",
        changedByUserId: params.reporterUserId ?? params.receivedByUserId ?? null,
        changeReason: "Initial reported location",
      });
    }

    const [rows] = await conn.execute(
      `
        SELECT
          ir.id,
          ir.public_uuid,
          ir.report_code,
          ir.reporter_user_id,
          ir.reporter_contact_id,
          ir.channel_id,
          ir.category_id,
          ir.reported_location_id,
          ir.summary,
          ir.description,
          ints.status_code AS intake_status,
          ir.final_disposition,
          ir.received_by_user_id,
          ir.reported_at,
          ir.created_at,
          ir.updated_at
        FROM intake_reports ir
        INNER JOIN intake_statuses ints ON ints.id = ir.current_status_id
        WHERE ir.id = ?
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
 * @returns {Promise<object | null>} row shape includes at least: id, public_uuid, intake_status, reporter_user_id, summary, channel_id, category_id, reported_location_id
 */
export async function findIntakeReportByPublicUuid(publicUuid) {
  const result = await query(
    `
      SELECT
        ir.id,
        ir.public_uuid,
        ir.report_code,
        ir.reporter_user_id,
        ir.reporter_contact_id,
        ir.channel_id,
        ir.category_id,
        ir.reported_location_id,
        ir.summary,
        ir.description,
        ints.status_code AS intake_status,
        ir.final_disposition,
        ir.received_by_user_id,
        ir.reported_at,
        ir.created_at,
        ir.updated_at
      FROM intake_reports ir
      INNER JOIN intake_statuses ints ON ints.id = ir.current_status_id
      WHERE ir.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );

  return result.rows[0] || null;
}

export async function listIntakeReportsByReporterUserId(reporterUserId, options = {}) {
  const geoSort = options.geoSort ?? null;
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance ? buildDistanceSortClause(geoSort.ref, "entity_loc.id") : null;
  const refJoinSql = useDistance
    ? `
      INNER JOIN locations entity_loc ON entity_loc.id = ir.reported_location_id
      ${distance.joinSql}
    `
    : "";
  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "ir.created_at DESC";
  const joinParams = useDistance ? distance.joinParams : [];

  const result = await query(
    `
      SELECT
        ir.public_uuid,
        ir.report_code,
        ir.summary,
        ir.description,
        ints.status_code AS intake_status,
        ir.final_disposition,
        ir.reported_at,
        ir.created_at,
        rc.channel_code,
        rcat.category_code,
        l.public_uuid AS location_public_uuid,
        l.latitude AS location_latitude,
        l.longitude AS location_longitude,
        l.address_text AS location_address_text,
        l.place_name AS location_place_name,
        l.admin_area_id AS location_admin_area_id,
        l.source AS location_source
        ${distanceSelect}
      FROM intake_reports ir
      INNER JOIN intake_statuses ints ON ints.id = ir.current_status_id
      INNER JOIN report_channels rc ON rc.id = ir.channel_id
      INNER JOIN report_categories rcat ON rcat.id = ir.category_id
      LEFT JOIN locations l ON l.id = ir.reported_location_id
      LEFT JOIN incident_report_links irl ON irl.intake_report_id = ir.id AND irl.unlinked_at IS NULL
      LEFT JOIN emergency_incidents ei ON ei.id = irl.incident_id
      LEFT JOIN incident_statuses ist ON ist.id = ei.current_status_id
      ${refJoinSql}
      WHERE ir.reporter_user_id = ?
      ORDER BY ${orderSql}
    `,
    [...joinParams, reporterUserId],
  );

  return result.rows.map((row) =>
    mapRowWithOptionalDistance(mapIntakeReportCore(row), row, geoSort),
  );
}

export async function findIntakeReportByPublicUuidForReporter(reportPublicUuid, reporterUserId) {
  const result = await query(
    `
      SELECT
        ir.id,
        ir.public_uuid,
        ir.report_code,
        ir.summary,
        ir.description,
        ints.status_code AS intake_status,
        ir.final_disposition,
        ir.reported_at,
        ir.created_at,
        ir.updated_at,
        rc.channel_code,
        rcat.category_code,
        l.public_uuid AS location_public_uuid,
        l.latitude AS location_latitude,
        l.longitude AS location_longitude,
        l.address_text AS location_address_text,
        l.place_name AS location_place_name,
        l.admin_area_id AS location_admin_area_id,
        l.source AS location_source
      FROM intake_reports ir
      INNER JOIN intake_statuses ints ON ints.id = ir.current_status_id
      INNER JOIN report_channels rc ON rc.id = ir.channel_id
      INNER JOIN report_categories rcat ON rcat.id = ir.category_id
      LEFT JOIN locations l ON l.id = ir.reported_location_id
      WHERE ir.public_uuid = ? AND ir.reporter_user_id = ?
      LIMIT 1
    `,
    [reportPublicUuid, reporterUserId],
  );
  return result.rows[0] ? mapIntakeReportWithLocation(result.rows[0]) : null;
}

export async function getIntakeReportStatsByReporterUserId(reporterUserId) {
  const result = await query(
    `
      SELECT
        COUNT(*) AS total_reports,
        SUM(
          CASE
            WHEN ei.id IS NOT NULL THEN CASE WHEN ist.is_terminal = FALSE THEN 1 ELSE 0 END
            WHEN ints.status_code IN ('received', 'under_review', 'linked_to_case', 'linked_to_incident')
            THEN 1
            ELSE 0
          END
        ) AS pending_reports,
        SUM(
          CASE
            WHEN ei.id IS NOT NULL THEN CASE WHEN ist.is_terminal = TRUE THEN 1 ELSE 0 END
            WHEN ints.status_code IN ('duplicate', 'false_report', 'closed')
            THEN 1
            ELSE 0
          END
        ) AS resolved_reports
      FROM intake_reports ir
      INNER JOIN intake_statuses ints ON ints.id = ir.current_status_id
      LEFT JOIN incident_report_links irl ON irl.intake_report_id = ir.id AND irl.unlinked_at IS NULL
      LEFT JOIN emergency_incidents ei ON ei.id = irl.incident_id
      LEFT JOIN incident_statuses ist ON ist.id = ei.current_status_id
      WHERE ir.reporter_user_id = ?
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

export async function updateIntakeReportLocation(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [intakeRows] = await conn.execute(
      `
        SELECT
          id,
          public_uuid,
          reporter_user_id,
          reported_location_id
        FROM intake_reports
        WHERE public_uuid = ?
        LIMIT 1
      `,
      [params.reportPublicUuid],
    );
    const intake = intakeRows[0];
    if (!intake) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }

    const isReporter =
      intake.reporter_user_id != null &&
      Number(intake.reporter_user_id) === Number(params.actorUserId);
    const isDispatcher = params.actorRoleCodes.includes(ROLE_CODES.DISPATCHER);
    const isSystemAdmin = params.actorRoleCodes.includes(ROLE_CODES.SYSTEM_ADMIN);
    if (!isReporter && !isDispatcher && !isSystemAdmin) {
      throw new BackendError(403, "FORBIDDEN", "Missing required permission");
    }

    let nextLocationId;
    if (params.locationId) {
      if (isReporter && !isDispatcher && !isSystemAdmin) {
        nextLocationId = await requireReporterOwnedLocationId(
          conn,
          params.locationId,
          params.actorUserId,
        );
      } else {
        nextLocationId = await requireLocationIdByPublicUuid(conn, params.locationId);
      }
    } else {
      let gpsResolvedAdminAreaId = null;
      if (params.location.admin_area_id == null) {
        const r = await resolveAdminAreaIdForLocationPayload({
          explicitAdminAreaId: null,
          latitude: params.location.latitude,
          longitude: params.location.longitude,
          pool,
        });
        gpsResolvedAdminAreaId = r.adminAreaId;
      }
      const adminAreaIdToUse = params.location.admin_area_id ?? gpsResolvedAdminAreaId ?? null;
      if (adminAreaIdToUse != null) {
        await requireAdministrativeAreaInTransaction(conn, adminAreaIdToUse);
      }
      const derivedAddress = await deriveAddressAndSourceForLocation({
        latitude: params.location.latitude,
        longitude: params.location.longitude,
        addressText: params.location.address_text ?? null,
        source:
          params.location.source ??
          (isDispatcher || isSystemAdmin ? "dispatcher_selected" : "user_shared"),
      });
      const inserted = await insertLocationInTransaction(conn, {
        admin_area_id: adminAreaIdToUse,
        latitude: params.location.latitude,
        longitude: params.location.longitude,
        address_text: derivedAddress.addressText,
        place_name: params.location.place_name ?? null,
        source:
          derivedAddress.source ??
          params.location.source ??
          (isDispatcher || isSystemAdmin ? "dispatcher_selected" : "user_shared"),
        created_by_user_id: params.actorUserId ?? null,
      });
      nextLocationId = Number(inserted.id);
    }

    const previousLocationId = intake.reported_location_id ?? null;
    if (previousLocationId != null && Number(previousLocationId) === Number(nextLocationId)) {
      await conn.commit();
    } else {
      await conn.execute(
        `
          UPDATE intake_reports
          SET reported_location_id = ?
          WHERE id = ?
        `,
        [nextLocationId, intake.id],
      );

      await insertIntakeLocationHistoryInTransaction(conn, {
        intakeReportId: intake.id,
        locationId: nextLocationId,
        previousLocationId,
        changeKind: previousLocationId == null ? "initial_create" : "location_patch",
        changedByUserId: params.actorUserId,
        changeReason:
          previousLocationId == null
            ? "Reported location added"
            : "Reported location updated",
      });
      await conn.commit();
    }

    const [rows] = await conn.execute(
      `
        SELECT
          ir.public_uuid,
          ir.report_code,
          ir.summary,
          ir.description,
          ints.status_code AS intake_status,
          ir.final_disposition,
          ir.reported_at,
          ir.created_at,
          rc.channel_code,
          rcat.category_code,
          l.public_uuid AS location_public_uuid,
          l.latitude AS location_latitude,
          l.longitude AS location_longitude,
          l.address_text AS location_address_text,
          l.place_name AS location_place_name,
          l.admin_area_id AS location_admin_area_id,
          l.source AS location_source
        FROM intake_reports ir
        INNER JOIN intake_statuses ints ON ints.id = ir.current_status_id
        INNER JOIN report_channels rc ON rc.id = ir.channel_id
        INNER JOIN report_categories rcat ON rcat.id = ir.category_id
        LEFT JOIN locations l ON l.id = ir.reported_location_id
        WHERE ir.id = ?
        LIMIT 1
      `,
      [intake.id],
    );
    return mapIntakeReportWithLocation(rows[0]);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function listIntakeReportLocationHistory(params) {
  const result = await query(
    `
      SELECT
        ilh.id,
        ilh.change_kind,
        ilh.changed_at,
        ilh.change_reason,
        ir.public_uuid AS intake_public_uuid,
        ru.id AS reporter_user_id,
        u.public_uuid AS changed_by_public_uuid,
        up.full_name AS changed_by_full_name,
        EXISTS (
          SELECT 1
          FROM user_roles ur
          INNER JOIN roles r ON r.id = ur.role_id
          WHERE ur.user_id = ilh.changed_by_user_id
            AND r.role_code IN ('dispatcher', 'system_admin')
        ) AS changed_by_dispatcher,
        l.public_uuid AS location_public_uuid,
        l.latitude AS location_latitude,
        l.longitude AS location_longitude,
        l.address_text AS location_address_text,
        l.place_name AS location_place_name,
        l.admin_area_id AS location_admin_area_id,
        l.source AS location_source,
        prev.public_uuid AS previous_location_public_uuid,
        prev.latitude AS previous_location_latitude,
        prev.longitude AS previous_location_longitude,
        prev.address_text AS previous_location_address_text,
        prev.place_name AS previous_location_place_name,
        prev.admin_area_id AS previous_location_admin_area_id,
        prev.source AS previous_location_source
      FROM intake_report_location_history ilh
      INNER JOIN intake_reports ir ON ir.id = ilh.intake_report_id
      LEFT JOIN users ru ON ru.id = ir.reporter_user_id
      LEFT JOIN users u ON u.id = ilh.changed_by_user_id
      LEFT JOIN user_profiles up ON up.user_id = u.id
      LEFT JOIN locations l ON l.id = ilh.location_id
      LEFT JOIN locations prev ON prev.id = ilh.previous_location_id
      WHERE ir.public_uuid = ?
      ORDER BY ilh.changed_at DESC, ilh.id DESC
    `,
    [params.reportPublicUuid],
  );

  const rows = result.rows;
  if (!rows.length) {
    const exists = await query(
      `SELECT reporter_user_id FROM intake_reports WHERE public_uuid = ? LIMIT 1`,
      [params.reportPublicUuid],
    );
    if (!exists.rows[0]) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }
    const isReporter =
      exists.rows[0].reporter_user_id != null &&
      Number(exists.rows[0].reporter_user_id) === Number(params.actorUserId);
    const isDispatcher = params.actorRoleCodes.includes(ROLE_CODES.DISPATCHER);
    const isSystemAdmin = params.actorRoleCodes.includes(ROLE_CODES.SYSTEM_ADMIN);
    if (!isReporter && !isDispatcher && !isSystemAdmin) {
      throw new BackendError(403, "FORBIDDEN", "Missing required permission");
    }
    return [];
  }

  const reporterUserId = rows[0].reporter_user_id;
  const isReporter =
    reporterUserId != null && Number(reporterUserId) === Number(params.actorUserId);
  const isDispatcher = params.actorRoleCodes.includes(ROLE_CODES.DISPATCHER);
  const isSystemAdmin = params.actorRoleCodes.includes(ROLE_CODES.SYSTEM_ADMIN);
  if (!isReporter && !isDispatcher && !isSystemAdmin) {
    throw new BackendError(403, "FORBIDDEN", "Missing required permission");
  }

  return rows.map((row) => ({
    id: String(row.id),
    change_kind: row.change_kind,
    changed_at: row.changed_at,
    change_reason: row.change_reason,
    changed_by: row.changed_by_public_uuid
      ? {
          public_uuid: row.changed_by_public_uuid,
          full_name: row.changed_by_full_name ?? null,
          actor_kind: row.changed_by_dispatcher ? "dispatcher" : "citizen",
        }
      : null,
    location: mapLocationFromRow(row),
    previous_location: row.previous_location_public_uuid
      ? {
          public_uuid: row.previous_location_public_uuid,
          latitude: Number(row.previous_location_latitude),
          longitude: Number(row.previous_location_longitude),
          address_text: row.previous_location_address_text,
          place_name: row.previous_location_place_name ?? null,
          admin_area_id:
            row.previous_location_admin_area_id != null
              ? Number(row.previous_location_admin_area_id)
              : null,
          source: row.previous_location_source ?? null,
        }
      : null,
  }));
}