import validate from "./validator.js";
import { createLocationBodySchema } from "./validationSchemas.js";

export const validateCreateLocation = validate("location", createLocationBodySchema);
