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
    const { auth, user, authz, actorUserId } = await authenticateAccessToken(accessToken);
    req.auth = auth;
    req.user = user;
    req.authz = authz;
    req.actorUserId = actorUserId;
    next();
  } catch (error) {
    next(error);
  }
}

function assertPermissionList(requiredPermissions) {
  if (!requiredPermissions.length) {
    throw new Error("At least one permission code is required");
  }
}

export function requirePermission(...permissionCodes) {
  assertPermissionList(permissionCodes);

  return (req, res, next) => {
    const userPermissions = req.authz?.permissions || [];
    const hasAllPermissions = permissionCodes.every((code) =>
      userPermissions.includes(code)
    );

    if (!hasAllPermissions) {
      return next(
        new BackendError(403, "FORBIDDEN", "Missing required permission")
      );
    }

    next();
  };
}

export function requireAnyPermission(...permissionCodes) {
  assertPermissionList(permissionCodes);

  return (req, res, next) => {
    const userPermissions = req.authz?.permissions || [];
    const hasAnyPermission = permissionCodes.some((code) =>
      userPermissions.includes(code)
    );

    if (!hasAnyPermission) {
      return next(
        new BackendError(403, "FORBIDDEN", "Missing required permission")
      );
    }

    next();
  };
}

export function requireRole(...roleCodes) {
  if (!roleCodes.length) {
    throw new Error("At least one role code is required");
  }

  return (req, res, next) => {
    const userRoles = req.authz?.roleCodes || [];
    const hasRole = roleCodes.some((roleCode) => userRoles.includes(roleCode));

    if (!hasRole) {
      return next(new BackendError(403, "FORBIDDEN", "Missing required role"));
    }

    next();
  };
}
