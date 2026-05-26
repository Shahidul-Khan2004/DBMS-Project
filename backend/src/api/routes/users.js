import express from "express";
import {
  requireAuth as defaultRequireAuth,
  requirePermission,
} from "../middlewares/auth.js";
import { getCurrentUser } from "../controllers/auth.js";
import { assignRoleToUser } from "../controllers/users.js";
import {
  validateUserRoleAssignment,
  validateUserRoleAssignmentParams,
} from "../validators/users.js";

export function createUsersRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();

  router.use(requireAuth);

  router.get("/me", getCurrentUser);
  router.post(
    "/:userId/roles",
    requirePermission("auth.manage_roles"),
    validateUserRoleAssignmentParams,
    validateUserRoleAssignment,
    assignRoleToUser,
  );

  return router;
}

export default createUsersRouter();
