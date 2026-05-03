import express from "express";
import { requireAuth, requirePermission } from "../middlewares/auth.js";
import { getCurrentUser } from "../controllers/auth.js";
import { assignRoleToUser } from "../controllers/users.js";
import {
  validateUserRoleAssignment,
  validateUserRoleAssignmentParams,
} from "../validators/users.js";

const router = express.Router();

router.use(requireAuth);

router.get("/me", getCurrentUser);
router.post(
  "/:userId/roles",
  requirePermission("auth.manage_roles"),
  validateUserRoleAssignmentParams,
  validateUserRoleAssignment,
  assignRoleToUser
);

export default router;
