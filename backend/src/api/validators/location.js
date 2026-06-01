import validate from "./validator.js";
import {
  createLocationBodySchema,
  locationPublicUuidParamSchema,
  saveLocationBodySchema,
} from "./validationSchemas.js";

export const validateCreateLocation = validate("location", createLocationBodySchema);
export const validateSaveLocation = validate("save location", saveLocationBodySchema);
export const validateLocationPublicUuidParam = validate(
  "location id",
  locationPublicUuidParamSchema,
  "params",
);
