import express from "express";
import {
  getAdministrativeAreaById,
  getAdministrativeAreaSearch,
} from "../controllers/reference.js";
import { requireAuth as defaultRequireAuth, requireAnyPermission } from "../middlewares/auth.js";
import {
  validateAdminAreaIdParam,
  validateAdminAreaSearch,
} from "../validators/disaster.js";

export function createReferenceRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();
  router.use(requireAuth);
  router.get(
    "/administrative-areas/search",
    requireAnyPermission("disaster.read", "disaster.create", "disaster.manage_affected_areas"),
    validateAdminAreaSearch,
    getAdministrativeAreaSearch,
  );
  router.get(
    "/administrative-areas/:adminAreaId",
    validateAdminAreaIdParam,
    getAdministrativeAreaById,
  );
  return router;
}

export default createReferenceRouter();
