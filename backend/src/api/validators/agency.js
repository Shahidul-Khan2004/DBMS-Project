import { z } from "zod";
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
import {
  validateCreateReliefRequest,
  validateDisasterUuidParam,
  validateOccupancySnapshot,
  validateStockReceipt,
} from "./disaster.js";

const uuid = z.string().uuid();

export const validateAgencyDisasterUuidParam = validateDisasterUuidParam;

export const validateAgencyShelterActivationParam = validate(
  "agency shelter activation",
  z.object({
    disasterPublicUuid: uuid,
    shelterActivationPublicUuid: uuid,
  }),
  "params",
);

export const validateAgencyHubActivationParam = validate(
  "agency relief hub activation",
  z.object({
    disasterPublicUuid: uuid,
    hubActivationPublicUuid: uuid,
  }),
  "params",
);

export { validateOccupancySnapshot as validateAgencyOccupancySnapshot };
export { validateCreateReliefRequest as validateAgencyCreateReliefRequest };
export { validateStockReceipt as validateAgencyStockReceipt };

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
