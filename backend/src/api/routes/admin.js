import express from "express";
import {
  requireAuth as defaultRequireAuth,
  requirePermission,
} from "../middlewares/auth.js";
import {
  getAdminAgencies,
  getAdminAgency,
  getAdminAgencyRepresentatives,
  patchAdminAgency,
  patchAdminActivateAgency,
  patchAdminDeactivateAgency,
  patchAdminDeactivateMembership,
  postAdminAgencyRepresentative,
  postAdminOnboardAgency,
} from "../controllers/adminAgency.js";
import {
  validateAdminAgencyUuidParam,
  validateAdminLinkRepresentative,
  validateAdminListAgenciesQuery,
  validateAdminMembershipUuidParam,
  validateAdminOnboardAgency,
  validateAdminPatchAgency,
} from "../validators/adminAgency.js";

export function createAdminRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();

  router.use(requireAuth);
  router.use(requirePermission("agency.manage"));

  router.post("/agencies/onboard", validateAdminOnboardAgency, postAdminOnboardAgency);
  router.get("/agencies", validateAdminListAgenciesQuery, getAdminAgencies);
  router.get("/agencies/:agencyPublicUuid", validateAdminAgencyUuidParam, getAdminAgency);
  router.patch(
    "/agencies/:agencyPublicUuid",
    validateAdminAgencyUuidParam,
    validateAdminPatchAgency,
    patchAdminAgency,
  );
  router.patch(
    "/agencies/:agencyPublicUuid/deactivate",
    validateAdminAgencyUuidParam,
    patchAdminDeactivateAgency,
  );
  router.patch(
    "/agencies/:agencyPublicUuid/activate",
    validateAdminAgencyUuidParam,
    patchAdminActivateAgency,
  );
  router.post(
    "/agencies/:agencyPublicUuid/representatives",
    validateAdminAgencyUuidParam,
    validateAdminLinkRepresentative,
    postAdminAgencyRepresentative,
  );
  router.get(
    "/agencies/:agencyPublicUuid/representatives",
    validateAdminAgencyUuidParam,
    getAdminAgencyRepresentatives,
  );
  router.patch(
    "/agency-memberships/:membershipPublicUuid/deactivate",
    validateAdminMembershipUuidParam,
    patchAdminDeactivateMembership,
  );

  return router;
}

export default createAdminRouter();
