import BackendError from "../../lib/BackendError.js";

export function notFound(req, res, next) {
  next(
    new BackendError(
      404,
      "ROUTE_NOT_FOUND",
      `Route ${req.method} ${req.originalUrl} not found`
    )
  );
}

export function errorHandler(err, req, res, next) {
    if (res.headersSent) return next(err);

    const statusCode = Number.isInteger(err.statusCode) ? err.statusCode : 500;
    const code = err.code || "INTERNAL_SERVER_ERROR";
    let message = err.message || "An unexpected error occurred.";

    if (statusCode >= 500) {
        message = "internal server error";
        console.error(err);
    }

    const body = { error: { code, message } };
    if (err.details) body.error.details = err.details;

    res.status(statusCode).json(body);
}