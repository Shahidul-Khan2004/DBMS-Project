import validate from "./validator.js";
import {
  adminAccountStatusBodySchema,
  adminListReporterRiskQuerySchema,
  adminReporterActionBodySchema,
  intakeReportVerificationBodySchema,
  operationsReportUuidParamSchema,
  userPublicUuidParamSchema,
} from "./validationSchemas.js";

export const validateIntakeReportVerification = validate(
  "intake report verification",
  intakeReportVerificationBodySchema,
);

export const validateIntakeReportVerificationParams = validate(
  "operations report id",
  operationsReportUuidParamSchema,
  "params",
);

export const validateReporterRiskForIntakeParams = validate(
  "operations report id",
  operationsReportUuidParamSchema,
  "params",
);

export const validateAdminListReporterRiskQuery = validate(
  "admin reporter risk list query",
  adminListReporterRiskQuerySchema,
  "query",
);

export const validateAdminReporterRiskDetailParams = validate(
  "admin reporter id",
  userPublicUuidParamSchema,
  "params",
);

export const validateAdminAccountStatusParams = validate(
  "admin user id",
  userPublicUuidParamSchema,
  "params",
);

export const validateAdminAccountStatusBody = validate(
  "admin account status",
  adminAccountStatusBodySchema,
);

export const validateAdminReporterActionParams = validate(
  "admin reporter id",
  userPublicUuidParamSchema,
  "params",
);

export const validateAdminReporterActionBody = validate(
  "admin reporter action",
  adminReporterActionBodySchema,
);
