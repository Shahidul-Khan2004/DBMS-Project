import validate from "./validator.js";
import {
  intakeEscalateServiceCaseToEmergencySchema,
  intakeReportPublicUuidParamSchema,
  operationsListServiceCasesQuerySchema,
  operationsPatchServiceCaseStatusSchema,
  operationsPostServiceCaseAssignmentSchema,
  operationsPostServiceCaseMessageSchema,
  operationsPostServiceCaseResolveSchema,
  operationsServiceCasePublicUuidParamSchema,
} from "./validationSchemas.js";

export { validateOperationsServiceCasesListGeoQuery as validateOperationsListServiceCasesQuery } from "./geoSort.js";

export const validateOperationsServiceCasePublicUuidParam = validate(
  "operations service case id",
  operationsServiceCasePublicUuidParamSchema,
  "params",
);

export const validateOperationsPatchServiceCaseStatus = validate(
  "operations patch service case status",
  operationsPatchServiceCaseStatusSchema,
);

export const validateOperationsPostServiceCaseMessage = validate(
  "operations post service case message",
  operationsPostServiceCaseMessageSchema,
);

export const validateOperationsPostServiceCaseAssignment = validate(
  "operations post service case assignment",
  operationsPostServiceCaseAssignmentSchema,
);

export const validateOperationsPostServiceCaseResolve = validate(
  "operations post service case resolve",
  operationsPostServiceCaseResolveSchema,
);

export const validateIntakeEscalateServiceCaseBody = validate(
  "intake escalate service case to emergency",
  intakeEscalateServiceCaseToEmergencySchema,
);

export const validateIntakeReportUuidParamForEscalate = validate(
  "intake report id (escalate)",
  intakeReportPublicUuidParamSchema,
  "params",
);

export const validateIntakeServiceCasePublicUuidParam = validate(
  "intake service case id",
  operationsServiceCasePublicUuidParamSchema,
  "params",
);

export const validateIntakePostServiceCaseMessage = validate(
  "intake post service case message",
  operationsPostServiceCaseMessageSchema,
);
