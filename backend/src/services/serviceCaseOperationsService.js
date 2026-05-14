import BackendError from "../lib/BackendError.js";
import { findUserByPublicUuid } from "../repositories/userRepo.js";
import {
  escalateIntakeServiceCaseToEmergencyInTransaction,
  getServiceCaseDetailForOperations,
  listMyServiceCasesByReporterUserId,
  listServiceCasesForOperations,
  patchServiceCaseStatusInTransaction,
  postCitizenServiceCaseMessageInTransaction,
  postServiceCaseAssignmentInTransaction,
  postServiceCaseMessageInTransaction,
  resolveServiceCaseInTransaction,
} from "../repositories/serviceCaseOperationsRepo.js";
import { createNotification } from "./notificationService.js";

function auditMetaFromRequest(req) {
  return {
    ipAddress: req.ip ?? null,
    userAgent: req.get?.("user-agent") ?? null,
  };
}

export async function operationsListServiceCases(query) {
  return listServiceCasesForOperations({
    status: query.status,
    categoryCode: query.categoryCode,
    assignedTo: query.assignedTo,
    limit: query.limit,
    offset: query.offset,
  });
}

export async function operationsGetServiceCase(publicUuid) {
  return getServiceCaseDetailForOperations(publicUuid);
}

export async function operationsPatchServiceCaseStatus(actorUserId, casePublicUuid, body, req) {
  const meta = auditMetaFromRequest(req);

  const { detail, fromStatusCode, toStatusCode, reporterUserId, caseId, caseCode } =
    await patchServiceCaseStatusInTransaction({
      casePublicUuid,
      actorUserId,
      statusCode: body.statusCode,
      note: body.note ?? null,
      ...meta,
    });

  try {
    if (reporterUserId != null) {
      const noteLine = body.note ? `\nNote: ${body.note}` : "";
      await createNotification({
        notificationType: "case_reply",
        templateCode: "intake_classified",
        templateVars: { case_code: caseCode },
        fallbackTitle: `Service case ${caseCode} status updated`,
        fallbackBody: `Your service case ${caseCode} has been updated from '${fromStatusCode}' to '${toStatusCode}'.${noteLine}\n\nPlease check the portal for full details.`,
        entityType: "service_case",
        entityId: caseId,
        recipientUserIds: [reporterUserId],
        createdByUserId: actorUserId,
        deliveryChannel: "both",
      });
    }
  } catch (err) {
    console.error("Failed to send service case status notification:", err);
  }

  return detail;
}

export async function operationsPostServiceCaseMessage(actorUserId, casePublicUuid, body, req) {
  const meta = auditMetaFromRequest(req);
  const result = await postServiceCaseMessageInTransaction({
    casePublicUuid,
    actorUserId,
    title: body.title,
    description: body.description ?? null,
    ...meta,
  });

  try {
    if (result.reporterUserId != null) {
      const line = "Dispatcher replied to your service case";
      await createNotification({
        notificationType: "case_reply",
        templateCode: "intake_classified",
        templateVars: { case_code: result.caseCode ?? "" },
        fallbackTitle: line,
        fallbackBody: line,
        entityType: "service_case",
        entityId: result.caseId,
        recipientUserIds: [result.reporterUserId],
        createdByUserId: actorUserId,
        deliveryChannel: "both",
      });
    }
  } catch (err) {
    console.error("Failed to send service case message notification:", err);
  }

  return result.message;
}

export async function operationsPostServiceCaseAssignment(actorUserId, casePublicUuid, body, req) {
  const meta = auditMetaFromRequest(req);
  return postServiceCaseAssignmentInTransaction({
    casePublicUuid,
    actorUserId,
    assignedToUserPublicUuid: body.assignedToUserPublicUuid,
    note: body.note ?? null,
    ...meta,
  });
}

export async function operationsPostServiceCaseResolve(actorUserId, casePublicUuid, body, req) {
  const meta = auditMetaFromRequest(req);
  const { detail, reporterUserId, caseId, caseCode } = await resolveServiceCaseInTransaction({
    casePublicUuid,
    actorUserId,
    resolutionType: body.resolutionType,
    resolutionText: body.resolutionText,
    recommendedFacilityId: body.recommendedFacilityId ?? null,
    statusNote: `Resolved (${body.resolutionType})`,
    ...meta,
  });

  try {
    if (reporterUserId != null) {
      await createNotification({
        notificationType: "case_resolved",
        templateCode: "intake_classified",
        templateVars: { case_code: caseCode },
        fallbackTitle: "Your service case has been resolved",
        fallbackBody: `Service case ${caseCode} has been resolved. Please check the portal for details.`,
        entityType: "service_case",
        entityId: caseId,
        recipientUserIds: [reporterUserId],
        createdByUserId: actorUserId,
        deliveryChannel: "both",
      });
    }
  } catch (err) {
    console.error("Failed to send service case resolved notification:", err);
  }

  return detail;
}

export async function listMyServiceCases(actorPublicUuid) {
  const userRow = await findUserByPublicUuid(actorPublicUuid);
  if (!userRow) {
    throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
  }
  const cases = await listMyServiceCasesByReporterUserId(userRow.id);
  return { service_cases: cases };
}

export async function intakePostServiceCaseMessage(actorUserId, casePublicUuid, body, req) {
  const meta = auditMetaFromRequest(req);
  const result = await postCitizenServiceCaseMessageInTransaction({
    casePublicUuid,
    actorUserId,
    title: body.title,
    description: body.description ?? null,
    ...meta,
  });

  const line = "Citizen replied to service case";
  try {
    if (result.assigneeUserId != null) {
      await createNotification({
        notificationType: "case_reply",
        templateCode: "intake_classified",
        templateVars: { case_code: result.caseCode ?? "" },
        fallbackTitle: line,
        fallbackBody: line,
        entityType: "service_case",
        entityId: result.caseId,
        recipientUserIds: [result.assigneeUserId],
        createdByUserId: actorUserId,
        deliveryChannel: "both",
      });
    }
  } catch (err) {
    console.error("Failed to send citizen service case message notification:", err);
  }

  return result.message;
}

export async function escalateIntakeFromServiceCase(actorUserId, reportPublicUuid, body, req) {
  const meta = auditMetaFromRequest(req);
  const result = await escalateIntakeServiceCaseToEmergencyInTransaction({
    reportPublicUuid,
    actorUserId,
    severityCode: body.severityCode,
    incidentTitle: body.incidentTitle ?? null,
    incidentDescription: body.incidentDescription ?? null,
    reportedAt: body.reportedAt ?? null,
    escalationReason: body.escalationReason,
    ...meta,
  });

  try {
    if (result.reporter_user_id != null) {
      await createNotification({
        notificationType: "case_escalated",
        templateCode: "intake_escalated",
        templateVars: { incident_code: result.incident.incident_code },
        fallbackTitle: "Your case was escalated to an emergency",
        fallbackBody: `Your service case has been escalated to emergency incident ${result.incident.incident_code}. Emergency responders have been notified. Please check the portal.`,
        entityType: "emergency_incident",
        entityId: result.incident_id,
        recipientUserIds: [result.reporter_user_id],
        createdByUserId: actorUserId,
        deliveryChannel: "both",
      });
    }
  } catch (err) {
    console.error("Failed to send service case escalation notification:", err);
  }

  return result;
}
