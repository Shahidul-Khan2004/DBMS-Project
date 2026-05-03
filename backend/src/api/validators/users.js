import validate from "./validator.js";
import {
  userRoleAssignmentParamsSchema,
  userRoleAssignmentSchema,
} from "./validationSchemas.js";

export const validateUserRoleAssignment = validate(
  "user role assignment",
  userRoleAssignmentSchema
);

export const validateUserRoleAssignmentParams = validate(
  "user role assignment params",
  userRoleAssignmentParamsSchema,
  "params"
);

