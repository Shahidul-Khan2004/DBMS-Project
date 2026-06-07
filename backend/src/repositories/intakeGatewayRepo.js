import BackendError from "../lib/BackendError.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
import {
  assertStatusTransitionAllowed,
  findStatusIdByCode,
} from "../lib/statusWorkflow.js";
import pool from "../config/db.js";

async function findCaseStatusId(conn, statusCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM case_statuses
      WHERE status_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [statusCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "CASE_STATUS_NOT_FOUND", "Initial case status not found");
  }
  return rows[0].id;
}

async function findIncidentStatusId(conn, statusCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM incident_statuses
      WHERE status_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [statusCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "INCIDENT_STATUS_NOT_FOUND", "Initial incident status not found");
  }
  return rows[0].id;
}

async function findSeverityLevelId(conn, severityCode) {
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM incident_severity_levels
      WHERE severity_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [severityCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "INCIDENT_SEVERITY_NOT_FOUND", "Invalid severityCode");
  }
  return rows[0].id;
}

export async function updateIntakeReportStatusInTransaction(
  conn,
  intakeReportId,
  statusCode,
  actorUserId,
  note,
) {
  const [currentRows] = await conn.execute(
    `
      SELECT ist.status_code AS status_code
      FROM intake_reports ir
      INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
      WHERE ir.id = ?
      LIMIT 1
    `,
    [intakeReportId],
  );
  if (!currentRows[0]) {
    throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
  }

  const { toStatusId: statusId } = await assertStatusTransitionAllowed(
    conn,
    "intake",
    currentRows[0].status_code,
    statusCode,
    { note },
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
    [intakeReportId, statusId, actorUserId ?? null, note ?? null],
  );
}

/** DB transitions require under_review before linked_to_case / linked_to_incident. */
export async function ensureIntakeUnderReviewIfReceived(
  conn,
  intakeReportId,
  intakeStatus,
  actorUserId,
  note = "Placed under review before linkage",
) {
  if (intakeStatus === "received") {
    await updateIntakeReportStatusInTransaction(
      conn,
      intakeReportId,
      "under_review",
      actorUserId,
      note,
    );
  }
}

/**
 * Transaction: service case from intake. SQL: docs/tickets-intake-gateway-fe-db.md (INTAKE-002).
 */
export async function createServiceCaseFromIntake(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const initialStatusId = await findCaseStatusId(
      conn,
      params.serviceCase.initialCaseStatusCode,
    );

    const [serviceCaseResult] = await conn.execute(
      `
        INSERT INTO service_cases (
          public_uuid,
          case_code,
          intake_report_id,
          reporter_user_id,
          parent_case_id,
          category_id,
          current_status_id,
          current_location_id,
          title,
          description,
          priority_level,
          source_channel_id
        )
        VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        params.serviceCase.publicUuid,
        params.serviceCase.caseCode,
        params.intake.id,
        params.intake.reporter_user_id,
        params.intake.category_id,
        initialStatusId,
        params.intake.reported_location_id ?? null,
        params.serviceCase.title,
        params.serviceCase.description ?? null,
        params.serviceCase.priorityLevel,
        params.intake.channel_id,
      ],
    );

    await conn.execute(
      `
        INSERT INTO case_status_history (
          case_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [
        serviceCaseResult.insertId,
        initialStatusId,
        params.actorUserId ?? null,
        `Created from intake ${params.intake.public_uuid}`,
      ],
    );

    await ensureIntakeUnderReviewIfReceived(
      conn,
      params.intake.id,
      params.intake.intake_status,
      params.actorUserId,
      "Under review before service case linkage",
    );

    await updateIntakeReportStatusInTransaction(
      conn,
      params.intake.id,
      "linked_to_case",
      params.actorUserId,
      `Linked to service case ${params.serviceCase.caseCode}`,
    );

    const [serviceCaseRows] = await conn.execute(
      `
        SELECT
          id,
          public_uuid,
          case_code,
          intake_report_id,
          reporter_user_id,
          category_id,
          current_status_id,
          current_location_id,
          title,
          description,
          priority_level,
          source_channel_id,
          created_at,
          updated_at
        FROM service_cases
        WHERE id = ?
        LIMIT 1
      `,
      [serviceCaseResult.insertId],
    );

    const [intakeRows] = await conn.execute(
      `
        SELECT
          ir.id,
          ir.public_uuid,
          ir.report_code,
          ir.reporter_user_id,
          ir.channel_id,
          ir.category_id,
          ir.reported_location_id,
          ir.summary,
          ir.description,
          ist.status_code AS intake_status,
          ir.final_disposition,
          ir.received_by_user_id,
          ir.reported_at,
          ir.created_at,
          ir.updated_at
        FROM intake_reports ir
        INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
        WHERE ir.id = ?
        LIMIT 1
      `,
      [params.intake.id],
    );

    await conn.commit();
    return {
      service_case: serviceCaseRows[0],
      intake: intakeRows[0],
    };
  } catch (error) {
    await conn.rollback();
    if (
      error?.code === "ER_DUP_ENTRY" &&
      error.message.includes("uq_service_cases_intake_report")
    ) {
      throw new BackendError(
        409,
        "INTAKE_ALREADY_LINKED",
        "Intake report is already linked to a service case",
      );
    }
    throw error;
  } finally {
    conn.release();
  }
}

/**
 * Transaction: emergency_calls + emergency_incidents + incident_report_links + intake updates. SQL: docs/tickets-intake-gateway-fe-db.md (INTAKE-003).
 */
export async function createEmergency999PathFromIntake(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const severityLevelId = await findSeverityLevelId(
      conn,
      params.incident.severityCode,
    );
    const incidentStatusId = await findIncidentStatusId(
      conn,
      params.incident.initialIncidentStatusCode,
    );

    const [emergencyCallResult] = await conn.execute(
      `
        INSERT INTO emergency_calls (
          intake_report_id,
          dispatcher_id,
          caller_phone_number,
          call_started_at,
          call_ended_at,
          triaged_at,
          call_status,
          recording_url
        )
        VALUES (?, ?, ?, ?, ?, ?, 'received', ?)
      `,
      [
        params.intake.id,
        params.emergencyCall.dispatcherId,
        params.emergencyCall.callerPhoneNumber ?? null,
        toMySqlDateTimeOrNull(params.emergencyCall.callStartedAt),
        toMySqlDateTimeOrNull(params.emergencyCall.callEndedAt),
        toMySqlDateTimeOrNull(params.emergencyCall.triagedAt),
        params.emergencyCall.recordingUrl ?? null,
      ],
    );

    const [incidentResult] = await conn.execute(
      `
        INSERT INTO emergency_incidents (
          public_uuid,
          incident_code,
          category_id,
          severity_level_id,
          current_status_id,
          current_location_id,
          final_outcome_id,
          origin_type,
          title,
          description,
          created_by_user_id,
          reported_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
      `,
      [
        params.incident.publicUuid,
        params.incident.incidentCode,
        params.intake.category_id,
        severityLevelId,
        incidentStatusId,
        params.intake.reported_location_id,
        params.incident.originType,
        params.incident.title,
        params.incident.description ?? null,
        params.actorUserId,
        toMySqlDateTimeOrNull(params.incident.reportedAt),
      ],
    );

    await conn.execute(
      `
        INSERT INTO incident_status_history (
          incident_id,
          status_id,
          changed_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?)
      `,
      [
        incidentResult.insertId,
        incidentStatusId,
        params.actorUserId ?? null,
        `Created from intake ${params.intake.public_uuid}`,
      ],
    );

    const [incidentReportLinkResult] = await conn.execute(
      `
        INSERT INTO incident_report_links (
          incident_id,
          intake_report_id,
          link_type,
          linked_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?, ?)
      `,
      [
        incidentResult.insertId,
        params.intake.id,
        params.incidentReportLink.linkType,
        params.actorUserId ?? null,
        `Linked during emergency intake classification for call ${emergencyCallResult.insertId}`,
      ],
    );

    await ensureIntakeUnderReviewIfReceived(
      conn,
      params.intake.id,
      params.intake.intake_status,
      params.actorUserId,
      "Under review before emergency incident linkage",
    );

    await updateIntakeReportStatusInTransaction(
      conn,
      params.intake.id,
      "linked_to_incident",
      params.actorUserId,
      `Linked to incident ${params.incident.incidentCode}`,
    );

    await conn.execute(
      `
        UPDATE emergency_calls
        SET call_status = 'linked_to_incident'
        WHERE id = ?
      `,
      [emergencyCallResult.insertId],
    );

    const [emergencyCallRows] = await conn.execute(
      `
        SELECT
          id,
          intake_report_id,
          dispatcher_id,
          caller_phone_number,
          call_started_at,
          call_ended_at,
          triaged_at,
          call_status,
          recording_url,
          transcript_text,
          created_at
        FROM emergency_calls
        WHERE id = ?
        LIMIT 1
      `,
      [emergencyCallResult.insertId],
    );
    const [incidentRows] = await conn.execute(
      `
        SELECT
          id,
          public_uuid,
          incident_code,
          category_id,
          severity_level_id,
          current_status_id,
          current_location_id,
          final_outcome_id,
          origin_type,
          title,
          description,
          created_by_user_id,
          reported_at,
          resolved_at,
          closed_at,
          created_at,
          updated_at
        FROM emergency_incidents
        WHERE id = ?
        LIMIT 1
      `,
      [incidentResult.insertId],
    );
    const [linkRows] = await conn.execute(
      `
        SELECT
          id,
          incident_id,
          intake_report_id,
          link_type,
          linked_by_user_id,
          linked_at,
          note
        FROM incident_report_links
        WHERE id = ?
        LIMIT 1
      `,
      [incidentReportLinkResult.insertId],
    );
    const [intakeRows] = await conn.execute(
      `
        SELECT
          ir.id,
          ir.public_uuid,
          ir.report_code,
          ir.reporter_user_id,
          ir.channel_id,
          ir.category_id,
          ir.reported_location_id,
          ir.summary,
          ir.description,
          ist.status_code AS intake_status,
          ir.final_disposition,
          ir.received_by_user_id,
          ir.reported_at,
          ir.created_at,
          ir.updated_at
        FROM intake_reports ir
        INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
        WHERE ir.id = ?
        LIMIT 1
      `,
      [params.intake.id],
    );

    await conn.commit();
    return {
      emergency_call: emergencyCallRows[0],
      emergency_incident: incidentRows[0],
      incident_report_link: linkRows[0],
      intake: intakeRows[0],
    };
  } catch (error) {
    await conn.rollback();
    if (
      error?.code === "ER_DUP_ENTRY" &&
      (error.message.includes("uq_emergency_calls_intake_report") ||
        error.message.includes("uq_incident_report_links_active_one_incident_per_report"))
    ) {
      throw new BackendError(
        409,
        "INTAKE_ALREADY_LINKED",
        "Intake report is already linked to an emergency path",
      );
    }
    throw error;
  } finally {
    conn.release();
  }
}

const TERMINAL_INCIDENT_STATUSES_GATEWAY = new Set(["resolved", "closed", "cancelled"]);

/**
 * Transaction: link a new gateway 999 intake to an existing active incident.
 * Creates/ensures the emergency_calls row, inserts into incident_report_links,
 * and moves the intake to linked_to_incident.
 * NEVER inserts into emergency_incidents.
 */
export async function linkGateway999IntakeToExistingIncident(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Load and validate the target incident.
    const [incidentRows] = await conn.execute(
      `
        SELECT
          ei.id AS id,
          ei.public_uuid AS public_uuid,
          ei.incident_code AS incident_code,
          ist.status_code AS status_code
        FROM emergency_incidents ei
        INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
        WHERE ei.public_uuid = ?
        LIMIT 1
      `,
      [params.incidentPublicUuid],
    );
    const incident = incidentRows[0] || null;
    if (!incident) {
      throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
    }
    if (TERMINAL_INCIDENT_STATUSES_GATEWAY.has(incident.status_code)) {
      throw new BackendError(
        409,
        "INCIDENT_NOT_LINKABLE",
        "Cannot link intake report to a terminal incident",
      );
    }

    // Load and validate the new intake.
    const [intakeRows] = await conn.execute(
      `
        SELECT
          ir.id AS id,
          ir.public_uuid AS public_uuid,
          ir.report_code AS report_code,
          ir.reporter_user_id AS reporter_user_id,
          ir.reported_location_id AS reported_location_id,
          ir.summary AS summary,
          ir.description AS description,
          ist2.status_code AS intake_status,
          ir.reported_at AS reported_at
        FROM intake_reports ir
        INNER JOIN intake_statuses ist2 ON ist2.id = ir.current_status_id
        WHERE ir.public_uuid = ?
        LIMIT 1
      `,
      [params.intakePublicUuid],
    );
    const intake = intakeRows[0] || null;
    if (!intake) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }

    // Require reported location.
    if (intake.reported_location_id == null) {
      throw new BackendError(
        422,
        "EMERGENCY_INCIDENT_REQUIRES_LOCATION",
        "Intake report has no location; cannot link to incident",
      );
    }

    // Reject an intake already linked to an incident.
    const [linkDup] = await conn.execute(
      `SELECT id FROM incident_report_links WHERE intake_report_id = ? AND unlinked_at IS NULL LIMIT 1`,
      [intake.id],
    );
    if (linkDup[0]) {
      throw new BackendError(
        409,
        "INTAKE_ALREADY_LINKED",
        "Intake report is already linked to an incident",
      );
    }

    // Create or ensure the emergency_calls row.
    const [existingCallRows] = await conn.execute(
      `SELECT id FROM emergency_calls WHERE intake_report_id = ? LIMIT 1`,
      [intake.id],
    );
    let emergencyCallId;
    if (existingCallRows[0]) {
      emergencyCallId = existingCallRows[0].id;
      await conn.execute(
        `
          UPDATE emergency_calls
          SET
            recording_url = COALESCE(recording_url, ?),
            caller_phone_number = COALESCE(caller_phone_number, ?),
            call_started_at = COALESCE(call_started_at, ?)
          WHERE id = ?
        `,
        [
          params.recordingUrl ?? null,
          params.callerPhoneNumber ?? null,
          toMySqlDateTimeOrNull(params.callStartedAt),
          emergencyCallId,
        ],
      );
    } else {
      const [callInsert] = await conn.execute(
        `
          INSERT INTO emergency_calls (
            intake_report_id,
            dispatcher_id,
            caller_phone_number,
            call_started_at,
            call_ended_at,
            triaged_at,
            call_status,
            recording_url
          )
          VALUES (?, ?, ?, ?, NULL, NULL, 'received', ?)
        `,
        [
          intake.id,
          params.dispatcherUserId,
          params.callerPhoneNumber ?? null,
          toMySqlDateTimeOrNull(params.callStartedAt) ?? toMySqlDateTimeOrNull(new Date().toISOString()),
          params.recordingUrl ?? null,
        ],
      );
      emergencyCallId = callInsert.insertId;
    }

    // Insert into incident_report_links.
    const [linkInsert] = await conn.execute(
      `
        INSERT INTO incident_report_links (
          incident_id,
          intake_report_id,
          link_type,
          linked_by_user_id,
          note
        )
        VALUES (?, ?, ?, ?, ?)
      `,
      [
        incident.id,
        intake.id,
        params.linkType ?? "supporting_report",
        params.actorUserId ?? null,
        params.note ?? `Linked as additional 999 call for incident ${incident.incident_code}`,
      ],
    );

    // Move intake status to linked_to_incident via the existing workflow.
    await ensureIntakeUnderReviewIfReceived(
      conn,
      intake.id,
      intake.intake_status,
      params.actorUserId,
      "Under review before incident linkage",
    );

    await updateIntakeReportStatusInTransaction(
      conn,
      intake.id,
      "linked_to_incident",
      params.actorUserId,
      `Linked to incident ${incident.incident_code}`,
    );

    // Update call status.
    await conn.execute(
      `UPDATE emergency_calls SET call_status = 'linked_to_incident' WHERE id = ?`,
      [emergencyCallId],
    );

    // Read back updated rows.
    const [callRows] = await conn.execute(
      `
        SELECT
          id,
          intake_report_id,
          dispatcher_id,
          caller_phone_number,
          call_started_at,
          call_ended_at,
          triaged_at,
          call_status,
          recording_url,
          transcript_text,
          created_at
        FROM emergency_calls
        WHERE id = ?
        LIMIT 1
      `,
      [emergencyCallId],
    );
    const [updatedLinkRows] = await conn.execute(
      `
        SELECT
          irl.id,
          irl.incident_id,
          irl.intake_report_id,
          irl.link_type,
          irl.linked_by_user_id,
          irl.linked_at,
          irl.note,
          ei.public_uuid AS incident_public_uuid,
          ei.incident_code AS incident_code
        FROM incident_report_links irl
        INNER JOIN emergency_incidents ei ON ei.id = irl.incident_id
        WHERE irl.id = ?
        LIMIT 1
      `,
      [linkInsert.insertId],
    );
    const [updatedIntakeRows] = await conn.execute(
      `
        SELECT
          ir.id,
          ir.public_uuid,
          ir.report_code,
          ir.reporter_user_id,
          ir.channel_id,
          ir.category_id,
          ir.reported_location_id,
          ir.summary,
          ir.description,
          ist2.status_code AS intake_status,
          ir.final_disposition,
          ir.received_by_user_id,
          ir.reported_at,
          ir.created_at,
          ir.updated_at
        FROM intake_reports ir
        INNER JOIN intake_statuses ist2 ON ist2.id = ir.current_status_id
        WHERE ir.id = ?
        LIMIT 1
      `,
      [intake.id],
    );

    await conn.commit();
    return {
      emergency_call: callRows[0],
      incident_report_link: updatedLinkRows[0],
      intake: updatedIntakeRows[0],
    };
  } catch (error) {
    await conn.rollback();
    if (
      error?.code === "ER_DUP_ENTRY" &&
      (error.message.includes("uq_emergency_calls_intake_report") ||
        error.message.includes("uq_incident_report_links_active_one_incident_per_report"))
    ) {
      throw new BackendError(
        409,
        "INTAKE_ALREADY_LINKED",
        "Intake report is already linked to an incident",
      );
    }
    throw error;
  } finally {
    conn.release();
  }
}

export async function ensureEmergencyCallForIntake(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [intakeRows] = await conn.execute(
      `
        SELECT id
        FROM intake_reports
        WHERE public_uuid = ?
        LIMIT 1
      `,
      [params.intakeReportPublicUuid],
    );
    const intake = intakeRows[0];
    if (!intake) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }

    const [existingRows] = await conn.execute(
      `
        SELECT id
        FROM emergency_calls
        WHERE intake_report_id = ?
        LIMIT 1
      `,
      [intake.id],
    );

    let emergencyCallId;
    if (existingRows[0]) {
      emergencyCallId = existingRows[0].id;
      await conn.execute(
        `
          UPDATE emergency_calls
          SET
            recording_url = COALESCE(recording_url, ?),
            caller_phone_number = COALESCE(caller_phone_number, ?),
            call_started_at = COALESCE(call_started_at, ?)
          WHERE id = ?
        `,
        [
          params.recordingUrl ?? null,
          params.callerPhoneNumber ?? null,
          toMySqlDateTimeOrNull(params.callStartedAt),
          emergencyCallId,
        ],
      );
    } else {
      const [insertResult] = await conn.execute(
        `
          INSERT INTO emergency_calls (
            intake_report_id,
            dispatcher_id,
            caller_phone_number,
            call_started_at,
            call_ended_at,
            triaged_at,
            call_status,
            recording_url
          )
          VALUES (?, ?, ?, ?, NULL, NULL, ?, ?)
        `,
        [
          intake.id,
          params.dispatcherUserId,
          params.callerPhoneNumber ?? null,
          toMySqlDateTimeOrNull(params.callStartedAt) ?? toMySqlDateTimeOrNull(new Date().toISOString()),
          params.callStatus ?? "triaged",
          params.recordingUrl ?? null,
        ],
      );
      emergencyCallId = insertResult.insertId;
    }

    const [rows] = await conn.execute(
      `
        SELECT
          id,
          intake_report_id,
          dispatcher_id,
          caller_phone_number,
          call_started_at,
          call_ended_at,
          triaged_at,
          call_status,
          recording_url,
          transcript_text,
          created_at
        FROM emergency_calls
        WHERE id = ?
        LIMIT 1
      `,
      [emergencyCallId],
    );

    await conn.commit();
    return rows[0];
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

const DISMISSABLE_INTAKE_STATUSES = new Set(["received", "under_review"]);
const DISMISS_DISPOSITIONS = new Set(["duplicate", "false_report"]);

export async function dismissIntakeReportInTransaction({
  intakeReportPublicUuid,
  actorUserId,
  disposition,
  note,
}) {
  if (!DISMISS_DISPOSITIONS.has(disposition)) {
    throw new BackendError(422, "INVALID_DISPOSITION", "Invalid dismiss disposition");
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute(
      `
        SELECT ir.id, ist.status_code AS intake_status
        FROM intake_reports ir
        INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
        WHERE ir.public_uuid = ?
        LIMIT 1
        FOR UPDATE
      `,
      [intakeReportPublicUuid],
    );

    if (!rows[0]) {
      throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
    }

    const intakeReportId = rows[0].id;
    const intakeStatus = rows[0].intake_status;

    if (!DISMISSABLE_INTAKE_STATUSES.has(intakeStatus)) {
      throw new BackendError(
        409,
        "INTAKE_NOT_DISMISSABLE",
        "Intake report cannot be dismissed in its current status",
      );
    }

    await updateIntakeReportStatusInTransaction(
      conn,
      intakeReportId,
      disposition,
      actorUserId,
      note?.trim() || null,
    );

    await conn.execute(
      `
        UPDATE intake_reports
        SET final_disposition = ?
        WHERE id = ?
      `,
      [disposition, intakeReportId],
    );

    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}