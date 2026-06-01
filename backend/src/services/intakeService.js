import { randomBytes, randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import { findUserByPublicUuid } from "../repositories/userRepo.js";
import {
  createIntakeReport,
  findIntakeReportByPublicUuid,
  findIntakeReportByPublicUuidForReporter,
  getIntakeReportStatsByReporterUserId,
  listIntakeReportLocationHistory,
  listIntakeReportsByReporterUserId,
  updateIntakeReportLocation,
} from "../repositories/intakeRepo.js";
import {
  createEmergency999PathFromIntake,
  createServiceCaseFromIntake,
  ensureEmergencyCallForIntake,
  linkGateway999IntakeToExistingIncident,
} from "../repositories/intakeGatewayRepo.js";
import { createNotification } from "./notificationService.js";
import { resolveGeoSortFromQuery } from "./geoSortService.js";

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const SERVICE_CASE_CLASSIFIABLE_STATUSES = new Set(["received", "under_review"]);
const EMERGENCY_CLASSIFIABLE_STATUSES = new Set([
  "received",
  "under_review",
  "linked_to_case",
]);

function assertValidReportPublicUuid(reportPublicUuid) {
  if (!UUID_REGEX.test(reportPublicUuid)) {
    throw new BackendError(400, "INVALID_REPORT_ID", "reportPublicUuid must be a UUID");
  }
}

function generateCode(prefix, maxLen = 60) {
  const t = Date.now().toString(36).toUpperCase();
  const r = randomBytes(4).toString("hex").toUpperCase();
  const raw = `${prefix}-${t}-${r}`;
  return raw.length <= maxLen ? raw : raw.slice(0, maxLen);
}

export async function createIntakeReportForUser(actorPublicUuid, body) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }

  const publicUuid = randomUUID();
  const reportCode = generateCode("IR");

  const report = await createIntakeReport({
    publicUuid,
    reportCode,
    reporterUserId: userRow.id,
    reporterContactId: null,
    channelCode: body.channelCode,
    categoryCode: body.categoryCode,
    summary: body.summary,
    description: body.description ?? null,
    reportedAt: body.reportedAt ?? null,
    receivedByUserId: null,
    location: body.location ?? null,
    locationId: body.locationId ?? null,
    createdByUserPublicUuid: actorPublicUuid,
  });

  // Confirm receipt to the submitter. Fire-and-forget — a notification
  // failure must never roll back the intake that was already committed.
  try {
    await createNotification({
      notificationType:  "case_reply",
      templateCode:      "intake_received",
      templateVars:      { report_code: reportCode },
      fallbackTitle:     "Your report has been received",
      fallbackBody:      `We have received your report (${reportCode}). You will be notified as it is reviewed.`,
      entityType:        "intake_report",
      entityId:          report.id,
      recipientUserIds:  [userRow.id],
      createdByUserId:   null,
      deliveryChannel:   "both",
    });
  } catch (err) {
    console.error("Failed to send intake_created notification:", err);
  }

  return report;
}

async function loadIntakeForClassification(reportPublicUuid, allowedStatuses) {
  assertValidReportPublicUuid(reportPublicUuid);
  const intake = await findIntakeReportByPublicUuid(reportPublicUuid);
  if (!intake) {
    throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
  }
  if (!allowedStatuses.has(intake.intake_status)) {
    throw new BackendError(
      409,
      "INTAKE_NOT_CLASSIFIABLE",
      "Intake report cannot be classified in its current status",
    );
  }
  return intake;
}

export async function classifyIntakeAsServiceCase(actorPublicUuid, reportPublicUuid, body) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }

  const intake = await loadIntakeForClassification(
    reportPublicUuid,
    SERVICE_CASE_CLASSIFIABLE_STATUSES,
  );

  if (intake.reported_location_id == null) {
    throw new BackendError(
      422,
      "SERVICE_CASE_REQUIRES_LOCATION",
      "Service case creation requires a reported location",
    );
  }

  if (intake.reporter_user_id == null) {
    throw new BackendError(
      422,
      "SERVICE_CASE_REQUIRES_REPORTER_USER",
      "Cannot open a service case for an intake with no reporter user; schema requires reporter_user_id on service_cases",
    );
  }

  const title = body.title?.trim() || intake.summary;
  const casePublicUuid = randomUUID();
  const caseCode = generateCode("SC");

  const result = await createServiceCaseFromIntake({
    intake,
    intakeReportPublicUuid: reportPublicUuid,
    actorUserId: userRow.id,
    serviceCase: {
      publicUuid: casePublicUuid,
      caseCode,
      title,
      description: body.description ?? intake.description ?? null,
      priorityLevel: body.priorityLevel ?? "medium",
      initialCaseStatusCode: "submitted",
    },
  });

  // Notify the reporter that their intake has been reviewed and a service case opened.
  try {
    await createNotification({
      notificationType:  "case_reply",
      templateCode:      "intake_classified",
      templateVars:      { case_code: result.service_case.case_code },
      fallbackTitle:     "Your report has been reviewed",
      fallbackBody:      `Your report has been reviewed and a service case (${result.service_case.case_code}) has been opened. Our team will follow up with you.`,
      entityType:        "service_case",
      entityId:          result.service_case.id,
      recipientUserIds:  [intake.reporter_user_id],
      createdByUserId:   userRow.id,
      deliveryChannel:   "both",
    });
  } catch (err) {
    console.error("Failed to send intake_classified notification:", err);
  }

  return result;
}

export async function classifyIntakeAsEmergency999(actorPublicUuid, reportPublicUuid, body) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }

  const intake = await loadIntakeForClassification(
    reportPublicUuid,
    EMERGENCY_CLASSIFIABLE_STATUSES,
  );

  const incidentPublicUuid = randomUUID();
  const incidentCode = generateCode("EMI");
  const callStartedAt = body.callStartedAt ?? new Date().toISOString();

  if (intake.reported_location_id == null) {
    throw new BackendError(
      422,
      "EMERGENCY_INCIDENT_REQUIRES_LOCATION",
      "Emergency incidents require a location; this intake has no reported_location_id. Create the intake with a location or extend INTAKE-003 to add operator-supplied coordinates.",
    );
  }

   const result = await createEmergency999PathFromIntake({
    intake,
    intakeReportPublicUuid: reportPublicUuid,
    actorUserId: userRow.id,
    emergencyCall: {
      dispatcherId: userRow.id,
      callerPhoneNumber: body.callerPhoneNumber ?? null,
      callStartedAt,
      callEndedAt: null,
      triagedAt: null,
    },
    incident: {
      publicUuid: incidentPublicUuid,
      incidentCode,
      severityCode: body.severityCode,
      initialIncidentStatusCode: "classified",
      originType: "emergency_call",
      title: body.incidentTitle?.trim() || intake.summary,
      description: body.incidentDescription ?? intake.description ?? null,
      reportedAt: intake.reported_at ?? null,
    },
    incidentReportLink: {
      linkType: "primary_report",
    },
  });

  try {
    await createNotification({
      notificationType:  "incident_update",
      templateCode:      "intake_escalated",
      templateVars:      { incident_code: result.emergency_incident.incident_code },
      fallbackTitle:     "Your report has been escalated",
      fallbackBody:      `Your intake report has been escalated to emergency incident ${result.emergency_incident.incident_code}.`,
      entityType:        "emergency_incident",
      entityId:          result.emergency_incident.id,
      recipientUserIds:  [intake.reporter_user_id],
      createdByUserId:   userRow.id,
      deliveryChannel:   "both",
    });
  } catch (err) {
    console.error("Failed to create emergency incident notification:", err);
  }

  return result;
}

export async function listMyIntakeReports(actorPublicUuid, query = {}) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }

  const geo = await resolveGeoSortFromQuery(query, { actorUserId: userRow.id });
  return listIntakeReportsByReporterUserId(userRow.id, { geoSort: geo.geoSort });
}

export async function getMyIntakeReportStats(actorPublicUuid) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }

  return getIntakeReportStatsByReporterUserId(userRow.id);
}

export async function getMyIntakeReportByPublicUuid(actorPublicUuid, reportPublicUuid) {
  assertValidReportPublicUuid(reportPublicUuid);
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }
  const intake = await findIntakeReportByPublicUuidForReporter(reportPublicUuid, userRow.id);
  if (!intake) {
    throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
  }
  return intake;
}

export async function patchIntakeReportLocation(actorPublicUuid, actorRoleCodes, reportPublicUuid, body) {
  assertValidReportPublicUuid(reportPublicUuid);
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }
  return updateIntakeReportLocation({
    reportPublicUuid,
    actorUserId: userRow.id,
    actorRoleCodes: actorRoleCodes ?? [],
    location: body.location ?? null,
    locationId: body.locationId ?? null,
  });
}

export async function getIntakeReportLocationHistory(
  actorPublicUuid,
  actorRoleCodes,
  reportPublicUuid,
) {
  assertValidReportPublicUuid(reportPublicUuid);
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }
  return listIntakeReportLocationHistory({
    reportPublicUuid,
    actorUserId: userRow.id,
    actorRoleCodes: actorRoleCodes ?? [],
  });
}

export async function createGateway999IntakeAndIncident(actorPublicUuid, body) {
  const intake = await createIntakeReportForUser(actorPublicUuid, {
    channelCode: "emergency_call",
    categoryCode: body.categoryCode,
    summary: body.summary,
    description: body.description,
    reportedAt: body.reportedAt,
    location: body.location ?? null,
    locationId: body.locationId ?? null,
  });

  const placeholderRecordingUrl = "placeholder://recording-pending";

  if (body.disposition === "service_case") {
    const serviceResult = await classifyIntakeAsServiceCase(
      actorPublicUuid,
      intake.public_uuid,
      {
        title: body.incidentTitle ?? body.summary,
        description: body.incidentDescription ?? body.description,
        priorityLevel: body.priorityLevel ?? "medium",
      },
    );
    const userRow = await findUserByPublicUuid(actorPublicUuid);
    const emergencyCall = await ensureEmergencyCallForIntake({
      intakeReportPublicUuid: intake.public_uuid,
      dispatcherUserId: userRow.id,
      callerPhoneNumber: body.callerPhoneNumber ?? null,
      callStartedAt: body.callStartedAt ?? new Date().toISOString(),
      callStatus: "triaged",
      recordingUrl: placeholderRecordingUrl,
    });
    return {
      intake,
      emergency_call: emergencyCall,
      disposition: "service_case",
      ...serviceResult,
    };
  }

  if (body.disposition === "existing_incident") {
    const userRow = await findUserByPublicUuid(actorPublicUuid);
    const linkResult = await linkGateway999IntakeToExistingIncident({
      intakePublicUuid: intake.public_uuid,
      actorUserId: userRow.id,
      incidentPublicUuid: body.incidentPublicUuid,
      callerPhoneNumber: body.callerPhoneNumber ?? null,
      callStartedAt: body.callStartedAt ?? new Date().toISOString(),
      recordingUrl: placeholderRecordingUrl,
      dispatcherUserId: userRow.id,
      linkType: body.linkType ?? "supporting_report",
      note: body.note ?? null,
    });
    return {
      intake,
      disposition: "existing_incident",
      ...linkResult,
    };
  }

  const emergencyResult = await classifyIntakeAsEmergency999(
    actorPublicUuid,
    intake.public_uuid,
    {
      severityCode: body.severityCode,
      incidentTitle: body.incidentTitle ?? body.summary,
      incidentDescription: body.incidentDescription ?? body.description,
      callerPhoneNumber: body.callerPhoneNumber ?? null,
      callStartedAt: body.callStartedAt ?? new Date().toISOString(),
    },
  );
  const emergencyCall = await ensureEmergencyCallForIntake({
    intakeReportPublicUuid: intake.public_uuid,
    dispatcherUserId: emergencyResult.emergency_call.dispatcher_id,
    callerPhoneNumber: body.callerPhoneNumber ?? null,
    callStartedAt: body.callStartedAt ?? new Date().toISOString(),
    callStatus: "linked_to_incident",
    recordingUrl: placeholderRecordingUrl,
  });
  return {
    intake,
    emergency_call: emergencyCall,
    disposition: "emergency_incident",
    ...emergencyResult,
  };
}