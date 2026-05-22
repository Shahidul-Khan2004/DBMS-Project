import express from "express";
import {
  classifyEmergency999,
  classifyServiceCase,
  createIntakeReport,
  getMyIntakeReportByPublicUuid,
  getMyIntakeReportLocationHistory,
  getMyIntakeReports,
  getMyIntakeReportStats,
  patchMyIntakeReportLocation,
} from "../controllers/intake.js";
import {
  requireAuth,
  requirePermission,
  requireRole,
} from "../middlewares/auth.js";
import {
  getIntakeServiceCaseMessages,
  getMyServiceCases,
  postIntakeReportEscalateToEmergency,
  postIntakeServiceCaseMessage,
} from "../controllers/intakeServiceCases.js";
import { getMyIncidents } from "../controllers/intakeIncidents.js";
import {
  validateIntakeEscalateServiceCaseBody,
  validateIntakePostServiceCaseMessage,
  validateIntakeReportUuidParamForEscalate,
  validateIntakeServiceCasePublicUuidParam,
} from "../validators/serviceCases.js";
import { ROLE_CODES } from "../../services/rbacService.js";
import {
  validateClassifyEmergency999,
  validateClassifyServiceCase,
  validateCreateIntakeReport,
  validateIntakeReportUuidParam,
  validatePatchIntakeReportLocation,
} from "../validators/intake.js";

const router = express.Router();

router.use(requireAuth);

router.get("/reports/my", getMyIntakeReports);
router.get("/reports/my/stats", getMyIntakeReportStats);
router.get("/reports/my/service-cases", getMyServiceCases);
router.get("/reports/my/incidents", getMyIncidents);
router.get(
  "/service-cases/:publicUuid/messages",
  validateIntakeServiceCasePublicUuidParam,
  getIntakeServiceCaseMessages,
);
router.post(
  "/service-cases/:publicUuid/messages",
  validateIntakeServiceCasePublicUuidParam,
  validateIntakePostServiceCaseMessage,
  postIntakeServiceCaseMessage,
);
router.get("/reports/:reportPublicUuid", validateIntakeReportUuidParam, getMyIntakeReportByPublicUuid);
router.get(
  "/reports/:reportPublicUuid/reported-location-history",
  validateIntakeReportUuidParam,
  getMyIntakeReportLocationHistory,
);
router.patch(
  "/reports/:reportPublicUuid/location",
  validateIntakeReportUuidParam,
  validatePatchIntakeReportLocation,
  patchMyIntakeReportLocation,
);

router.post(
  "/reports",
  validateCreateIntakeReport,
  createIntakeReport,
);
const operatorRoles = [ROLE_CODES.DISPATCHER, ROLE_CODES.SYSTEM_ADMIN];

router.post(
  "/reports/:reportPublicUuid/classify/service-case",
  requireRole(...operatorRoles),
  validateClassifyServiceCase,
  classifyServiceCase,
);
router.post(
  "/reports/:reportPublicUuid/classify/emergency",
  requireRole(...operatorRoles),
  validateClassifyEmergency999,
  classifyEmergency999,
);

router.post(
  "/reports/:reportPublicUuid/escalate",
  requireRole(...operatorRoles),
  requirePermission("case.escalate"),
  requirePermission("incident.create"),
  validateIntakeReportUuidParamForEscalate,
  validateIntakeEscalateServiceCaseBody,
  postIntakeReportEscalateToEmergency,
);

export default router;