import express from "express";
import {
  classifyEmergency999,
  classifyServiceCase,
  createIntakeReport,
} from "../controllers/intake.js";
import {
  forbidEmergencyUrgencyWithoutIncidentClassify,
  requireAuth,
  requirePermission,
} from "../middlewares/auth.js";
import {
  validateClassifyEmergency999,
  validateClassifyServiceCase,
  validateCreateIntakeReport,
} from "../validators/intake.js";

const router = express.Router();

router.use(requireAuth);

router.post(
  "/reports",
  validateCreateIntakeReport,
  forbidEmergencyUrgencyWithoutIncidentClassify,
  createIntakeReport,
);
router.post(
  "/reports/:reportPublicUuid/classify/service-case",
  validateClassifyServiceCase,
  classifyServiceCase,
);
router.post(
  "/reports/:reportPublicUuid/classify/emergency",
  requirePermission("incident.create"),
  validateClassifyEmergency999,
  classifyEmergency999,
);

export default router;
