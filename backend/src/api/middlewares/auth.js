import BackendError from "../../lib/BackendError.js";
import { authenticateAccessToken } from "../../services/authService.js";

function extractBearerToken(req) {
  const authorization = req.get("authorization");

  if (!authorization) return null;

  const [scheme, token] = authorization.trim().split(/\s+/);

  if (scheme?.toLowerCase() !== "bearer" || !token) {
    return null;
  }

  return token;
}

export async function requireAuth(req, res, next) {
  const accessToken = extractBearerToken(req);

  if (!accessToken) {
    return next(
      new BackendError(401, "AUTH_HEADER_INVALID", "Missing or invalid Authorization header")
    );
  }

  try {
    const { auth, user } = await authenticateAccessToken(accessToken);
    req.auth = auth;
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}
