import express from "express";
import {
  getLocationByPublicUuid,
  getMyLocations,
  getLocationReverse,
  getLocationSearch,
  postLocation,
} from "../controllers/locations.js";
import { requireAuth as defaultRequireAuth } from "../middlewares/auth.js";
import {
  validateCreateLocation,
  validateLocationPublicUuidParam,
} from "../validators/location.js";
import { validateCitizenGeoListQuery } from "../validators/geoSort.js";

export function createLocationsRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();

  router.use(requireAuth);

  router.post("/", validateCreateLocation, postLocation);
  router.get("/my", validateCitizenGeoListQuery, getMyLocations);
  router.get("/search", getLocationSearch);
  router.get("/reverse", getLocationReverse);
  router.get("/:publicUuid", validateLocationPublicUuidParam, getLocationByPublicUuid);

  return router;
}

export default createLocationsRouter();
