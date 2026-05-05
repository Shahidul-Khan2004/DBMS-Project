import {
  classifyEmergency999Schema,
  classifyServiceCaseSchema,
  createIntakeReportSchema,
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
