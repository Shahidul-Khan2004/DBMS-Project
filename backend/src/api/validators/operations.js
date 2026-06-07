import validate from "./validator.js";
import {
  classifyEmergency999Schema,
  dismissIntakeReportSchema,
  gateway999CreateSchema,
  operationsLinkIntakeToIncidentSchema,
  operationsUnlinkIntakeFromIncidentSchema,
  operationsCreateIncidentSchema,
  operationsIncidentNoteSchema,
  operationsIncidentUuidParamSchema,
  operationsListIncidentsQuerySchema,
  operationsListIntakeReportsQuerySchema,
  paginationQuerySchema,
  operationsPatchIncidentStatusSchema,
  operationsReportUuidParamSchema,
} from "./validationSchemas.js";
import BackendError from "../../lib/BackendError.js";

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

export const validateOperationsDismissIntakeReport = validate(
  "operations dismiss intake report",
  dismissIntakeReportSchema,
);

export const validateOperationsCreateIncident = validate(
  "operations create incident",
  operationsCreateIncidentSchema,
);

export { validateOperationsIncidentsListGeoQuery as validateOperationsListIncidentsQuery } from "./geoSort.js";

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

export const validateOperationsListIncidentNotesQuery = validate(
  "operations incident notes list query",
  paginationQuerySchema,
  "query",
);

export const validateOperationsLinkIntakeToIncident = validate(
  "operations link intake report",
  operationsLinkIntakeToIncidentSchema,
);

export const validateOperationsGateway999Create = validate(
  "operations gateway 999 create",
  gateway999CreateSchema,
);

export function validateOperationsUnlinkIntakeFromIncident(req, res, next) {
  const schema = operationsUnlinkIntakeFromIncidentSchema;
  
  // Validate params
  const paramsResult = schema.shape.params.safeParse(req.params);
  if (!paramsResult.success) {
    return next(
      new BackendError(
        422,
        "VALIDATION_ERROR",
        "invalid operations unlink intake request params",
        paramsResult.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        }))
      )
    );
  }

  // Validate body
  const bodyResult = schema.shape.body.safeParse(req.body);
  if (!bodyResult.success) {
    return next(
      new BackendError(
        422,
        "VALIDATION_ERROR",
        "invalid operations unlink intake request body",
        bodyResult.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        }))
      )
    );
  }

  req.validated ??= {};
  req.validated.params = paramsResult.data;
  req.validated.body = bodyResult.data;
  next();
}
