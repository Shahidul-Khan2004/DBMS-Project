import express from "express";
import {
  requireAuth as defaultRequireAuth,
  requirePermission,
} from "../middlewares/auth.js";
import {
  getAdminReporterRiskDetail,
  getAdminReporterRisks,
  patchAdminUserAccountStatus,
  postAdminReporterAction,
} from "../controllers/adminReporterRisk.js";
import {
  validateAdminAccountStatusBody,
  validateAdminAccountStatusParams,
  validateAdminListReporterRiskQuery,
  validateAdminReporterActionBody,
  validateAdminReporterActionParams,
  validateAdminReporterRiskDetailParams,
} from "../validators/reporterRisk.js";

export function createAdminReporterRiskRouter({
  requireAuth = defaultRequireAuth,
} = {}) {
  const router = express.Router();

  router.use(requireAuth);

  router.get(
    "/reporters/risk",
    requirePermission("reporter_risk.manage"),
    validateAdminListReporterRiskQuery,
    getAdminReporterRisks,
  );

  router.get(
    "/reporters/:userPublicUuid/risk",
    requirePermission("reporter_risk.manage"),
    validateAdminReporterRiskDetailParams,
    getAdminReporterRiskDetail,
  );

  router.patch(
    "/users/:userPublicUuid/account-status",
    requirePermission("reporter_risk.manage"),
    validateAdminAccountStatusParams,
    validateAdminAccountStatusBody,
    patchAdminUserAccountStatus,
  );

  router.post(
    "/reporters/:userPublicUuid/actions",
    requirePermission("reporter_risk.manage"),
    validateAdminReporterActionParams,
    validateAdminReporterActionBody,
    postAdminReporterAction,
  );

  return router;
}

export default createAdminReporterRiskRouter();
