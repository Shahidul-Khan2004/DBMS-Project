import express from "express";
import {
  classifyEmergency999,
  classifyServiceCase,
  createIntakeReport,
  getMyIntakeReports,
  getMyIntakeReportStats,
} from "../controllers/intake.js";
import {
  forbidEmergencyUrgencyWithoutIncidentClassify,
  requireAuth,
  requireRole,
} from "../middlewares/auth.js";
import { ROLE_CODES } from "../../services/rbacService.js";
import {
  validateClassifyEmergency999,
  validateClassifyServiceCase,
  validateCreateIntakeReport,
} from "../validators/intake.js";

const router = express.Router();

router.use(requireAuth);

router.get("/reports/my", getMyIntakeReports);
router.get("/reports/my/stats", getMyIntakeReportStats);

router.post(
  "/reports",
  validateCreateIntakeReport,
  forbidEmergencyUrgencyWithoutIncidentClassify,
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

export default router;
