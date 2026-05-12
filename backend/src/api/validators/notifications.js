/**
 * validators/notifications.js
 * ============================
 * Exported middleware validators for notification routes.
 *
 * Conventions followed (matches operations.js and users.js validators):
 *   - Each export is a validate() call with (schemaName, schema, requestProperty)
 *   - Schemas live in validationSchemas.js; this file only wires them to the factory
 *   - On failure, validate() throws BackendError(422, "VALIDATION_ERROR", ...) automatically
 *   - On success, validated data is stored at req.validated.query / req.validated.params
 */

import validate from "./validator.js";
import {
  listNotificationsQuerySchema,
  notificationRecipientIdParamSchema,
} from "./validationSchemas.js";

/**
 * Validates query params for GET /notifications/my.
 * Validates: unread_only (boolean), limit (integer 1-100), offset (integer ≥ 0).
 * All fields are optional — missing fields fall back to service-layer defaults.
 */
export const validateListNotificationsQuery = validate(
  "notifications list query",
  listNotificationsQuerySchema,
  "query",
);

/**
 * Validates the :notificationRecipientId route param for PATCH /notifications/:id/read.
 * Coerces the string param to a positive integer.
 * Returns 422 if the value is missing, zero, negative, or not a number.
 */
export const validateNotificationRecipientIdParam = validate(
  "notification recipient id",
  notificationRecipientIdParamSchema,
  "params",
);