import validate from "./validator.js";
import {
  classifyEmergency999Schema,
  operationsCreateIncidentSchema,
  operationsIncidentNoteSchema,
  operationsIncidentUuidParamSchema,
  operationsListIncidentsQuerySchema,
  operationsListIntakeReportsQuerySchema,
  operationsPatchIncidentStatusSchema,
  operationsReportUuidParamSchema,
} from "./validationSchemas.js";

export const validateOperationsListIntakeQuery = validate(
  "operations intake list query",
  operationsListIntakeReportsQuerySchema,
  "query",
);

export const validateOperationsReportUuidParam = validate(
  "operations report id",
  operationsReportUuidParamSchema,
  "params",
);

export const validateOperationsPromoteEmergency = validate(
  "operations promote emergency",
  classifyEmergency999Schema,
);

export const validateOperationsCreateIncident = validate(
  "operations create incident",
  operationsCreateIncidentSchema,
);

export const validateOperationsListIncidentsQuery = validate(
  "operations incidents list query",
  operationsListIncidentsQuerySchema,
  "query",
);

export const validateOperationsIncidentUuidParam = validate(
  "operations incident id",
  operationsIncidentUuidParamSchema,
  "params",
);

export const validateOperationsPatchIncidentStatus = validate(
  "operations patch incident status",
  operationsPatchIncidentStatusSchema,
);

export const validateOperationsIncidentNote = validate(
  "operations incident note",
  operationsIncidentNoteSchema,
);
