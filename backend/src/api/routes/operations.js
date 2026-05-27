import express from "express";
import {
  requireAuth as defaultRequireAuth,
  requireAnyPermission,
  requirePermission,
} from "../middlewares/auth.js";
import {
  createOperationsIncident,
  getOperationsIncident,
  getOperationsIncidentNotes,
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
  validateOperationsListIncidentNotesQuery,
  validateOperationsLinkIntakeToIncident,
  validateOperationsListIntakeQuery,
  validateOperationsPatchIncidentStatus,
  validateOperationsPromoteEmergency,
  validateOperationsReportUuidParam,
} from "../validators/operations.js";
import { getOperationsDispatcherOverview } from "../controllers/operationsDispatcherOverview.js";
import {
  getOperationsAgencyWorkload,
  getOperationsAvailableUnits,
  getOperationsIncidentResponseTiming,
  patchOperationsDispatchStatus,
  postOperationsIncidentAgency,
  postOperationsIncidentDispatch,
} from "../controllers/operationsDispatch.js";
import {
  validateOperationsAddIncidentAgency,
  validateOperationsAvailableUnitsQuery,
  validateOperationsCreateDispatch,
  validateOperationsDispatchUuidParam,
  validateOperationsPatchDispatchStatus,
} from "../validators/operationsDispatch.js";
import {
  getOperationsServiceCase,
  getOperationsServiceCaseMessages,
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

export function createOperationsRouter({ requireAuth = defaultRequireAuth } = {}) {
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

router.get(
  "/incidents/:incidentPublicUuid/notes",
  requireAnyPermission("incident.create", "incident.update_status"),
  validateOperationsIncidentUuidParam,
  validateOperationsListIncidentNotesQuery,
  getOperationsIncidentNotes,
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

router.post(
  "/incidents/:incidentPublicUuid/agencies",
  requirePermission("incident.assign_agency"),
  validateOperationsIncidentUuidParam,
  validateOperationsAddIncidentAgency,
  postOperationsIncidentAgency,
);

router.get(
  "/units/available",
  requirePermission("dispatch.create"),
  validateOperationsAvailableUnitsQuery,
  getOperationsAvailableUnits,
);

router.post(
  "/incidents/:incidentPublicUuid/dispatches",
  requirePermission("dispatch.create"),
  validateOperationsIncidentUuidParam,
  validateOperationsCreateDispatch,
  postOperationsIncidentDispatch,
);

router.patch(
  "/dispatches/:dispatchPublicUuid/status",
  requirePermission("dispatch.update_status"),
  validateOperationsDispatchUuidParam,
  validateOperationsPatchDispatchStatus,
  patchOperationsDispatchStatus,
);

router.get(
  "/agencies/workload",
  requireAnyPermission("dispatch.create", "incident.assign_agency"),
  getOperationsAgencyWorkload,
);

router.get(
  "/incidents/:incidentPublicUuid/response-timing",
  requireAnyPermission("dispatch.create", "incident.assign_agency"),
  validateOperationsIncidentUuidParam,
  getOperationsIncidentResponseTiming,
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

router.get(
  "/service-cases/:publicUuid/messages",
  requirePermission("case.respond"),
  validateOperationsServiceCasePublicUuidParam,
  getOperationsServiceCaseMessages,
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

  return router;
}

export default createOperationsRouter();
