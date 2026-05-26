import BackendError from "../../lib/BackendError.js";
import { resolveAgencyContextForUser } from "../../services/agencyService.js";

export async function requireAgencyContext(req, res, next) {
  try {
    if (!req.actorUserId) {
      return next(new BackendError(401, "AUTH_HEADER_INVALID", "Authentication required"));
    }

    req.agencyContext = await resolveAgencyContextForUser(req.actorUserId);
    next();
  } catch (error) {
    next(error);
  }
}
