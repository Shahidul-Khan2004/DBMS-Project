import BackendError from "../lib/BackendError.js";
import { query } from "../config/db.js";
import {
  applyIncidentStatusChange,
  insertIncidentOperatorNote,
  linkIntakeReportToIncident,
  promoteIntakeReportToEmergencyIncident,
  createIncidentAdminStandalone,
  getIncidentDetailForOperations,
  listIncidentsForOperations,
  listIncidentOperatorNotes,
  listMyIncidentsByReporterUserId,
  getIncidentReporterUserIds,
} from "../repositories/incidentOperationsRepo.js";
import { findUserByPublicUuid } from "../repositories/userRepo.js";
import {
  findIntakeReportDetailForOperations,
  listIntakeReportsForOperations,
} from "../repositories/operationsIntakeRepo.js";
import { listIntakeReportLocationHistory } from "../repositories/intakeRepo.js";
import { findIntakeReportByPublicUuid } from "../repositories/intakeRepo.js";
import { createNotification } from "./notificationService.js";

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

export async function operationsGetIntakeReportLocationHistory(actorUserId, reportPublicUuid) {
  return listIntakeReportLocationHistory({
    reportPublicUuid,
    actorUserId,
    actorRoleCodes: ["dispatcher"],
  });
}

export async function operationsCreateStandaloneIncident(actorUserId, body) {
  const incident = await createIncidentAdminStandalone({
    actorUserId,
    categoryCode:           body.categoryCode           ?? null,
    severityCode:           body.severityCode,
    title:                  body.title                  ?? null,
    description:            body.description            ?? null,
    location:               body.location               ?? null,
    locationId:             body.locationId             ?? null,
    reportedAt:             body.reportedAt             ?? null,
    intakeReportPublicUuid: body.intakeReportPublicUuid ?? null,
  });

  // Notify the creating operator that the incident is live.
  // Also notify any reporter linked via an intake (when intakeReportPublicUuid was supplied).
  try {
    const recipientUserIds = new Set([actorUserId]);

    if (body.intakeReportPublicUuid) {
      const reporterIds = await getIncidentReporterUserIds(incident.public_uuid);
      reporterIds.forEach((id) => recipientUserIds.add(id));
    }

    await createNotification({
      notificationType:  "incident_update",
      templateCode:      "incident_created",
      templateVars:      { incident_code: incident.incident_code },
      fallbackTitle:     "Emergency incident created",
      fallbackBody:      `Emergency incident ${incident.incident_code} has been created and is now active.`,
      entityType:        "emergency_incident",
      entityId:          incident.id,
      recipientUserIds:  [...recipientUserIds],
      createdByUserId:   actorUserId,
      deliveryChannel:   "both",
    });
  } catch (err) {
    console.error("Failed to send incident_created notification:", err);
  }

  return incident;
}

export async function operationsPromoteIntakeEmergency(
  actorUserId,
  reportPublicUuid,
  body,
) {
  const incident = await promoteIntakeReportToEmergencyIncident({
    intakeReportPublicUuid: reportPublicUuid,
    actorUserId,
    severityCode:           body.severityCode,
    incidentTitle:          body.incidentTitle,
    incidentDescription:    body.incidentDescription,
    reportedAt:             body.reportedAt,
  });

  // Notify the original reporter. We reload the intake by public UUID because
  // promoteIntakeReportToEmergencyIncident returns only the incident detail.
  try {
    const intake = await findIntakeReportByPublicUuid(reportPublicUuid);
    if (intake?.reporter_user_id != null) {
      await createNotification({
        notificationType:  "incident_update",
        templateCode:      "intake_escalated",
        templateVars:      { incident_code: incident.incident_code },
        fallbackTitle:     "Your report has been escalated to an emergency",
        fallbackBody:      `Your intake report has been escalated to emergency incident ${incident.incident_code}. Emergency responders have been notified.`,
        entityType:        "emergency_incident",
        entityId:          incident.id,
        recipientUserIds:  [intake.reporter_user_id],
        createdByUserId:   actorUserId,
        deliveryChannel:   "both",
      });
    }
  } catch (err) {
    console.error("Failed to send escalation notification (operations promote):", err);
  }

  return incident;
}

export async function operationsListIncidents(filters) {
  return listIncidentsForOperations(filters);
}

export async function listMyIncidents(actorPublicUuid) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }
  const incidents = await listMyIncidentsByReporterUserId(userRow.id);
  return { incidents };
}

export async function operationsGetIncident(publicUuid) {
  return getIncidentDetailForOperations(publicUuid);
}

export async function operationsListIncidentNotes(incidentPublicUuid, query) {
  return listIncidentOperatorNotes(incidentPublicUuid, query);
}

export async function operationsPatchIncidentStatus(actorUserId, incidentPublicUuid, body) {
  const fromCode = await getCurrentIncidentStatus(incidentPublicUuid);
  if (!fromCode) {
    throw new BackendError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  }

  assertOutcomeForTerminal(body.statusCode, body.outcomeCode ?? null);

  const incident = await applyIncidentStatusChange({
    incidentPublicUuid,
    actorUserId,
    statusCode:  body.statusCode,
    note:        body.note       ?? null,
    outcomeCode: body.outcomeCode ?? null,
  });

  // Notify all reporters linked to this incident about the status change.
  try {
    const reporterUserIds = await getIncidentReporterUserIds(incidentPublicUuid);
    if (reporterUserIds.length > 0) {
      // note_line is either empty or "\nNote: <text>" — the template uses {{note_line}}
      const noteLine = body.note ? `\nNote: ${body.note}` : "";
      await createNotification({
        notificationType:  "incident_update",
        templateCode:      "incident_status_updated",
        templateVars:      {
          incident_code: incident.incident_code,
          from_status:   fromCode,
          to_status:     body.statusCode,
          note_line:     noteLine,
        },
        fallbackTitle:     `Incident status updated to '${body.statusCode}'`,
        fallbackBody:      `Incident ${incident.incident_code} has been updated from '${fromCode}' to '${body.statusCode}'.${noteLine}`,
        entityType:        "emergency_incident",
        entityId:          incident.id,
        recipientUserIds:  reporterUserIds,
        createdByUserId:   actorUserId,
        deliveryChannel:   "both",
      });
    }
  } catch (err) {
    console.error("Failed to send incident status notification:", err);
  }

  return incident;
}

export async function operationsAddIncidentNote(actorUserId, incidentPublicUuid, body) {
  const row = await insertIncidentOperatorNote({
    incidentPublicUuid,
    actorUserId,
    title:       body.title,
    description: body.description ?? null,
    eventTime:   body.eventTime   ?? null,
  });
  return row;
}

export async function operationsLinkIntakeReport(
  actorUserId,
  incidentPublicUuid,
  body,
) {
  return linkIntakeReportToIncident({
    actorUserId,
    incidentPublicUuid,
    intakeReportPublicUuid: body.intakeReportPublicUuid,
    linkType: body.linkType ?? "supporting_report",
    note: body.note ?? null,
  });
}
