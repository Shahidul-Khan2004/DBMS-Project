import BackendError from "../lib/BackendError.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";
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

async function updateIntakeStatus(conn, intakeReportId, status, actorUserId, note) {
  await conn.execute(
    `
      UPDATE intake_reports
      SET intake_status = ?
      WHERE id = ?
    `,
    [status, intakeReportId],
  );

  await conn.execute(
    `
      INSERT INTO intake_report_status_history (
        intake_report_id,
        status,
        changed_by_user_id,
        note
      )
      VALUES (?, ?, ?, ?)
    `,
    [intakeReportId, status, actorUserId ?? null, note ?? null],
  );
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

    await updateIntakeStatus(
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
          id,
          public_uuid,
          report_code,
          reporter_user_id,
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
          call_status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'received')
      `,
      [
        params.intake.id,
        params.emergencyCall.dispatcherId,
        params.emergencyCall.callerPhoneNumber ?? null,
        toMySqlDateTimeOrNull(params.emergencyCall.callStartedAt),
        toMySqlDateTimeOrNull(params.emergencyCall.callEndedAt),
        toMySqlDateTimeOrNull(params.emergencyCall.triagedAt),
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

    await updateIntakeStatus(
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
          id,
          public_uuid,
          report_code,
          reporter_user_id,
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
        error.message.includes("uq_incident_report_links_one_incident_per_report"))
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
