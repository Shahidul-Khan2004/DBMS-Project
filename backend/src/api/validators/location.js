import validate from "./validator.js";
import {
  createLocationBodySchema,
  locationPublicUuidParamSchema,
} from "./validationSchemas.js";

export const validateCreateLocation = validate("location", createLocationBodySchema);
export const validateLocationPublicUuidParam = validate(
  "location id",
  locationPublicUuidParamSchema,
  "params",
);
