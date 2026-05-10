import BackendError from "../lib/BackendError.js";
import { query } from "../config/db.js";
import {
  applyIncidentStatusChange,
  insertIncidentOperatorNote,
  promoteIntakeReportToEmergencyIncident,
  createIncidentAdminStandalone,
  getIncidentDetailForOperations,
  listIncidentsForOperations,
} from "../repositories/incidentOperationsRepo.js";
import {
  findIntakeReportDetailForOperations,
  listIntakeReportsForOperations,
} from "../repositories/operationsIntakeRepo.js";

const TERMINAL_STATUSES = new Set(["resolved", "closed", "cancelled"]);

const ALLOWED_TRANSITIONS = {
  reported: new Set(["classified", "cancelled"]),
  classified: new Set(["in_progress", "resolved", "closed", "cancelled"]),
  in_progress: new Set(["resolved", "closed", "cancelled"]),
};

async function getCurrentIncidentStatus(publicUuid) {
  const result = await query(
    `
      SELECT ist.status_code AS status_code
      FROM emergency_incidents ei
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
      WHERE ei.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  return result.rows[0]?.status_code ?? null;
}

function assertStatusTransition(fromCode, toCode) {
  if (!fromCode || !toCode) {
    throw new BackendError(422, "INVALID_STATUS_CODE", "Invalid status transition");
  }
  if (fromCode === toCode) {
    throw new BackendError(409, "INVALID_STATUS_TRANSITION", "Incident already has this status");
  }
  if (TERMINAL_STATUSES.has(fromCode)) {
    throw new BackendError(
      409,
      "INVALID_STATUS_TRANSITION",
      "Cannot change status of a terminal incident",
    );
  }
  const allowed = ALLOWED_TRANSITIONS[fromCode];
  if (!allowed || !allowed.has(toCode)) {
    throw new BackendError(
      409,
      "INVALID_STATUS_TRANSITION",
      `Cannot transition incident from '${fromCode}' to '${toCode}'`,
    );
  }
}

function assertOutcomeForTerminal(statusCode, outcomeCode) {
  if (
    outcomeCode &&
    statusCode !== "resolved" &&
    statusCode !== "closed" &&
    statusCode !== "cancelled"
  ) {
    throw new BackendError(
      422,
      "INVALID_OUTCOME",
      "outcomeCode is only accepted when transitioning to resolved, closed, or cancelled",
    );
  }
}

export async function operationsListIntakeReports(queryFilters) {
  return listIntakeReportsForOperations(queryFilters);
}

export async function operationsGetIntakeReport(publicUuid) {
  return findIntakeReportDetailForOperations(publicUuid);
}

export async function operationsCreateStandaloneIncident(actorUserId, body) {
  return createIncidentAdminStandalone({
    actorUserId,
    categoryCode: body.categoryCode ?? null,
    severityCode: body.severityCode,
    title: body.title ?? null,
    description: body.description ?? null,
    location: body.location ?? null,
    locationId: body.locationId ?? null,
    reportedAt: body.reportedAt ?? null,
    intakeReportPublicUuid: body.intakeReportPublicUuid ?? null,
  });
}

export async function operationsPromoteIntakeEmergency(
  actorUserId,
  reportPublicUuid,
  body,
) {
  return promoteIntakeReportToEmergencyIncident({
    intakeReportPublicUuid: reportPublicUuid,
    actorUserId,
    severityCode: body.severityCode,
    incidentTitle: body.incidentTitle,
    incidentDescription: body.incidentDescription,
    reportedAt: body.reportedAt,
  });
}

export async function operationsListIncidents(filters) {
  return listIncidentsForOperations(filters);
}

export async function operationsGetIncident(publicUuid) {
  return getIncidentDetailForOperations(publicUuid);
}

export async function operationsPatchIncidentStatus(actorUserId, incidentPublicUuid, body) {
  const fromCode = await getCurrentIncidentStatus(incidentPublicUuid);
  if (!fromCode) {
    throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  }

  assertStatusTransition(fromCode, body.statusCode);
  assertOutcomeForTerminal(body.statusCode, body.outcomeCode ?? null);

  return applyIncidentStatusChange({
    incidentPublicUuid,
    actorUserId,
    statusCode: body.statusCode,
    note: body.note ?? null,
    outcomeCode: body.outcomeCode ?? null,
  });
}

export async function operationsAddIncidentNote(actorUserId, incidentPublicUuid, body) {
  const row = await insertIncidentOperatorNote({
    incidentPublicUuid,
    actorUserId,
    title: body.title,
    description: body.description ?? null,
    eventTime: body.eventTime ?? null,
  });
  return row;
}
