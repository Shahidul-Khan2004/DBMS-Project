import validate from "./validator.js";
import {
  operationsAddIncidentAgencySchema,
  operationsAvailableUnitsQuerySchema,
  operationsCreateDispatchSchema,
  operationsDispatchUuidParamSchema,
  operationsPatchDispatchStatusSchema,
} from "./validationSchemas.js";

export const validateOperationsAddIncidentAgency = validate(
  "operations add incident agency",
  operationsAddIncidentAgencySchema,
);

export const validateOperationsAvailableUnitsQuery = validate(
  "operations available units query",
  operationsAvailableUnitsQuerySchema,
  "query",
);

export const validateOperationsCreateDispatch = validate(
  "operations create dispatch",
  operationsCreateDispatchSchema,
);

export const validateOperationsDispatchUuidParam = validate(
  "operations dispatch id",
  operationsDispatchUuidParamSchema,
  "params",
);

export const validateOperationsPatchDispatchStatus = validate(
  "operations patch dispatch status",
  operationsPatchDispatchStatusSchema,
);
