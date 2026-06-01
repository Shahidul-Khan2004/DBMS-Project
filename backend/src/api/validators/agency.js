import validate from "./validator.js";
import {
  agencyCreateResponseLogSchema,
  agencyCreateUnitSchema,
  agencyPatchUnitSchema,
  agencyPatchUnitStatusSchema,
  incidentPublicUuidParamSchema,
  operationsDispatchUuidParamSchema,
  operationsPatchDispatchStatusSchema,
  paginationQuerySchema,
  unitPublicUuidParamSchema,
} from "./validationSchemas.js";

export const validateAgencyListQuery = validate("agency list query", paginationQuerySchema, "query");
export { validateAgencyUnitsListQuery } from "./geoSort.js";
export const validateAgencyUnitUuidParam = validate(
  "agency unit id",
  unitPublicUuidParamSchema,
  "params",
);
export const validateAgencyIncidentUuidParam = validate(
  "agency incident id",
  incidentPublicUuidParamSchema,
  "params",
);
export const validateAgencyDispatchUuidParam = validate(
  "agency dispatch id",
  operationsDispatchUuidParamSchema,
  "params",
);
export const validateAgencyPatchDispatchStatus = validate(
  "agency patch dispatch status",
  operationsPatchDispatchStatusSchema,
);
export const validateAgencyCreateUnit = validate("agency create unit", agencyCreateUnitSchema);
export const validateAgencyPatchUnit = validate("agency patch unit", agencyPatchUnitSchema);
export const validateAgencyPatchUnitStatus = validate(
  "agency patch unit status",
  agencyPatchUnitStatusSchema,
);
export const validateAgencyCreateResponseLog = validate(
  "agency create response log",
  agencyCreateResponseLogSchema,
);
