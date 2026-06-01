import express from "express";
import {
  getFacilities,
  getFacility,
  patchActivateFacility,
  patchDeactivateFacility,
  postFacility,
  putFacilityCapabilities,
  putFacilityDefaultCapacities,
} from "../controllers/facilityAdmin.js";
import { requireAuth as defaultRequireAuth, requirePermission } from "../middlewares/auth.js";
import {
  validateCreateFacility,
  validateFacilityCapabilities,
  validateFacilityDefaultCapacities,
} from "../validators/facility.js";
import { validateAdminFacilitiesListQuery } from "../validators/geoSort.js";
import validate from "../validators/validator.js";
import { z } from "zod";

const validateFacilityUuidParam = validate(
  "facilityUuidParam",
  z.object({ facilityPublicUuid: z.string().uuid() }),
  "params",
);

export function createFacilitiesRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();
  router.use(requireAuth);
  router.use(requirePermission("facility.manage"));

  router.get("/", validateAdminFacilitiesListQuery, getFacilities);
  router.post("/", validateCreateFacility, postFacility);
  router.get("/:facilityPublicUuid", validateFacilityUuidParam, getFacility);
  router.put(
    "/:facilityPublicUuid/capabilities",
    validateFacilityUuidParam,
    validateFacilityCapabilities,
    putFacilityCapabilities,
  );
  router.put(
    "/:facilityPublicUuid/default-capacities",
    validateFacilityUuidParam,
    validateFacilityDefaultCapacities,
    putFacilityDefaultCapacities,
  );
  router.patch(
    "/:facilityPublicUuid/deactivate",
    validateFacilityUuidParam,
    patchDeactivateFacility,
  );
  router.patch(
    "/:facilityPublicUuid/activate",
    validateFacilityUuidParam,
    patchActivateFacility,
  );
  return router;
}

export default createFacilitiesRouter();
