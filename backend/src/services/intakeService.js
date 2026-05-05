import { randomBytes, randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import { findUserByPublicUuid } from "../repositories/userRepo.js";
import {
  createIntakeReport,
  findIntakeReportByPublicUuid,
} from "../repositories/intakeRepo.js";
import {
  createEmergency999PathFromIntake,
  createServiceCaseFromIntake,
} from "../repositories/intakeGatewayRepo.js";

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const CLASSIFIABLE_STATUSES = new Set(["received", "under_review"]);

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

  return createIntakeReport({
    publicUuid,
    reportCode,
    reporterUserId: userRow.id,
    reporterContactId: null,
    channelCode: body.channelCode,
    categoryCode: body.categoryCode,
    summary: body.summary,
    description: body.description ?? null,
    urgencyType: body.urgencyType ?? "unknown",
    reportedAt: body.reportedAt ?? null,
    receivedByUserId: null,
    location: body.location ?? null,
    createdByUserPublicUuid: actorPublicUuid,
  });
}

async function loadIntakeForClassification(reportPublicUuid) {
  assertValidReportPublicUuid(reportPublicUuid);
  const intake = await findIntakeReportByPublicUuid(reportPublicUuid);
  if (!intake) {
    throw new BackendError(404, "INTAKE_REPORT_NOT_FOUND", "Intake report not found");
  }
  if (!CLASSIFIABLE_STATUSES.has(intake.intake_status)) {
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

  const intake = await loadIntakeForClassification(reportPublicUuid);

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

  return createServiceCaseFromIntake({
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
}

export async function classifyIntakeAsEmergency999(actorPublicUuid, reportPublicUuid, body) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }

  const intake = await loadIntakeForClassification(reportPublicUuid);

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

  return createEmergency999PathFromIntake({
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
      initialIncidentStatusCode: "reported",
      originType: "emergency_call",
      title: body.incidentTitle?.trim() || intake.summary,
      description: body.incidentDescription ?? intake.description ?? null,
      reportedAt: intake.reported_at ?? null,
    },
    incidentReportLink: {
      linkType: "primary_report",
    },
  });
}
