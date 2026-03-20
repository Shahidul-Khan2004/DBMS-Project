import BackendError from "../../lib/BackendError";

export function notFound(req, res, next) {
    next(
        new BackendError(
            404,
            "Not Found",
            `Route ${req.originalUrl} not found while using ${req.method} method.`
        )
    );
}

export function errorHandler(err, req, res, next) {
    if (res.headersSent) return next(err);

    const name = err.name || "Undefined Error";
    const code = Number.isInteger(err.code) ? err.code : 500;
    const type = err.type || "Internal Server Error";
    let message = err.message || "An unexpected error occurred.";

    if (code >= 500) {
        message = "internal server error";
        console.error(err);
    }

    const body = { [name]: { type, message } };
    if (err.details) body[name].details = err.details;

    res.status(code).json(body);
}