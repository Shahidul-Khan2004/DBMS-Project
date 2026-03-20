import BackendError from "../../lib/BackendError.js";

export default function validate(schemaName, schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      return next(
        new BackendError(
          422,
          "VALIDATION_ERROR",
          `invalid ${schemaName} data`,
          result.error.issues.map((issue) => ({
            field: issue.path.join("."),
            message: issue.message,
          }))
        )
      );
    }

    req.body = result.data;
    next();
  };
}