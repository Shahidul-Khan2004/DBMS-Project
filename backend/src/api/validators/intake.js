import {
  classifyEmergency999Schema,
  classifyServiceCaseSchema,
  createIntakeReportSchema,
  intakeReportLocationPatchSchema,
  intakeReportPublicUuidParamSchema,
} from "./validationSchemas.js";
import validate from "./validator.js";

export const validateCreateIntakeReport = validate("intake report", createIntakeReportSchema);
export const validateClassifyServiceCase = validate(
  "service case classification",
  classifyServiceCaseSchema,
);
export const validateClassifyEmergency999 = validate(
  "emergency (999) classification",
  classifyEmergency999Schema,
);
export const validateIntakeReportUuidParam = validate(
  "intake report id",
  intakeReportPublicUuidParamSchema,
  "params",
);
export const validatePatchIntakeReportLocation = validate(
  "patch intake report location",
  intakeReportLocationPatchSchema,
);
