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
  postOperationsIncidentNote,
  promoteIntakeToEmergency,
} from "../controllers/operationsIncidents.js";
import {
  getOperationsIntakeReport,
  listOperationsIntakeReports,
} from "../controllers/operationsIntakeReports.js";
import {
  validateOperationsCreateIncident,
  validateOperationsIncidentNote,
  validateOperationsIncidentUuidParam,
  validateOperationsListIncidentsQuery,
  validateOperationsListIntakeQuery,
  validateOperationsPatchIncidentStatus,
  validateOperationsPromoteEmergency,
  validateOperationsReportUuidParam,
} from "../validators/operations.js";

const router = express.Router();

router.use(requireAuth);

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

router.post(
  "/intake-reports/:reportPublicUuid/promote/emergency",
  requirePermission("incident.create"),
  requirePermission("incident.classify"),
  validateOperationsReportUuidParam,
  validateOperationsPromoteEmergency,
  promoteIntakeToEmergency,
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

export default router;
