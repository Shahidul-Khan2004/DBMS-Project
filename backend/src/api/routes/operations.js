import express from "express";
import {
  requireAuth,
  requireAnyPermission,
  requirePermission,
} from "../middlewares/auth.js";
import {
  createOperationsIncident,
  getOperationsIncident,
  listOperationsIncidents,
  patchOperationsIncidentStatus,
  postGateway999IntakeAndIncident,
  postLinkIntakeReportToIncident,
  postOperationsIncidentNote,
  promoteIntakeToEmergency,
} from "../controllers/operationsIncidents.js";
import {
  getOperationsIntakeReportLocationHistory,
  getOperationsIntakeReport,
  listOperationsIntakeReports,
} from "../controllers/operationsIntakeReports.js";
import {
  validateOperationsCreateIncident,
  validateOperationsGateway999Create,
  validateOperationsIncidentNote,
  validateOperationsIncidentUuidParam,
  validateOperationsListIncidentsQuery,
  validateOperationsLinkIntakeToIncident,
  validateOperationsListIntakeQuery,
  validateOperationsPatchIncidentStatus,
  validateOperationsPromoteEmergency,
  validateOperationsReportUuidParam,
} from "../validators/operations.js";
import { getOperationsDispatcherOverview } from "../controllers/operationsDispatcherOverview.js";
import {
  getOperationsServiceCase,
  listOperationsServiceCases,
  patchOperationsServiceCaseStatus,
  postOperationsServiceCaseAssignment,
  postOperationsServiceCaseMessage,
  postOperationsServiceCaseResolve,
} from "../controllers/operationsServiceCases.js";
import {
  validateOperationsListServiceCasesQuery,
  validateOperationsPatchServiceCaseStatus,
  validateOperationsPostServiceCaseAssignment,
  validateOperationsPostServiceCaseMessage,
  validateOperationsPostServiceCaseResolve,
  validateOperationsServiceCasePublicUuidParam,
} from "../validators/serviceCases.js";

const router = express.Router();

router.use(requireAuth);

router.get(
  "/dispatcher/overview",
  requirePermission("incident.classify"),
  getOperationsDispatcherOverview,
);

router.get(
  "/intake-reports",
  requirePermission("incident.classify"),
  validateOperationsListIntakeQuery,
  listOperationsIntakeReports,
);

router.get(
  "/intake-reports/:reportPublicUuid",
  requirePermission("incident.classify"),
  validateOperationsReportUuidParam,
  getOperationsIntakeReport,
);

router.get(
  "/intake-reports/:reportPublicUuid/reported-location-history",
  requirePermission("incident.classify"),
  validateOperationsReportUuidParam,
  getOperationsIntakeReportLocationHistory,
);

router.post(
  "/intake-reports/:reportPublicUuid/promote/emergency",
  requirePermission("incident.create"),
  requirePermission("incident.classify"),
  validateOperationsReportUuidParam,
  validateOperationsPromoteEmergency,
  promoteIntakeToEmergency,
);

router.post(
  "/gateway/999/intake-and-incident",
  requirePermission("incident.classify"),
  validateOperationsGateway999Create,
  postGateway999IntakeAndIncident,
);

router.post(
  "/incidents",
  requirePermission("incident.create"),
  validateOperationsCreateIncident,
  createOperationsIncident,
);

router.get(
  "/incidents",
  requireAnyPermission("incident.create", "incident.update_status"),
  validateOperationsListIncidentsQuery,
  listOperationsIncidents,
);

router.get(
  "/incidents/:incidentPublicUuid",
  requireAnyPermission("incident.create", "incident.update_status"),
  validateOperationsIncidentUuidParam,
  getOperationsIncident,
);

router.patch(
  "/incidents/:incidentPublicUuid/status",
  requirePermission("incident.update_status"),
  validateOperationsIncidentUuidParam,
  validateOperationsPatchIncidentStatus,
  patchOperationsIncidentStatus,
);

router.post(
  "/incidents/:incidentPublicUuid/notes",
  requirePermission("incident.update_status"),
  validateOperationsIncidentUuidParam,
  validateOperationsIncidentNote,
  postOperationsIncidentNote,
);

router.post(
  "/incidents/:incidentPublicUuid/intake-reports",
  requireAnyPermission("incident.create", "incident.update_status"),
  validateOperationsIncidentUuidParam,
  validateOperationsLinkIntakeToIncident,
  postLinkIntakeReportToIncident,
);

router.get(
  "/service-cases",
  requirePermission("case.respond"),
  validateOperationsListServiceCasesQuery,
  listOperationsServiceCases,
);

router.get(
  "/service-cases/:publicUuid",
  requirePermission("case.respond"),
  validateOperationsServiceCasePublicUuidParam,
  getOperationsServiceCase,
);

router.patch(
  "/service-cases/:publicUuid/status",
  requirePermission("case.respond"),
  validateOperationsServiceCasePublicUuidParam,
  validateOperationsPatchServiceCaseStatus,
  patchOperationsServiceCaseStatus,
);

router.post(
  "/service-cases/:publicUuid/messages",
  requirePermission("case.respond"),
  validateOperationsServiceCasePublicUuidParam,
  validateOperationsPostServiceCaseMessage,
  postOperationsServiceCaseMessage,
);

router.post(
  "/service-cases/:publicUuid/assignments",
  requirePermission("case.assign"),
  validateOperationsServiceCasePublicUuidParam,
  validateOperationsPostServiceCaseAssignment,
  postOperationsServiceCaseAssignment,
);

router.post(
  "/service-cases/:publicUuid/resolve",
  requirePermission("case.respond"),
  validateOperationsServiceCasePublicUuidParam,
  validateOperationsPostServiceCaseResolve,
  postOperationsServiceCaseResolve,
);

export default router;
