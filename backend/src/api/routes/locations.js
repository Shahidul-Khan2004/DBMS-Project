import express from "express";
import {
  getLocationByPublicUuid,
  getMyLocations,
  getLocationReverse,
  getLocationSearch,
  postLocation,
  saveLocation,
  unsaveLocation,
} from "../controllers/locations.js";
import { requireAuth as defaultRequireAuth } from "../middlewares/auth.js";
import {
  validateCreateLocation,
  validateLocationPublicUuidParam,
  validateSaveLocation,
} from "../validators/location.js";

export function createLocationsRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();

  router.use(requireAuth);

  router.post("/", validateCreateLocation, postLocation);
  router.get("/my", getMyLocations);
  router.get("/search", getLocationSearch);
  router.get("/reverse", getLocationReverse);
  router.post("/:publicUuid/save", validateLocationPublicUuidParam, validateSaveLocation, saveLocation);
  router.delete("/:publicUuid/save", validateLocationPublicUuidParam, unsaveLocation);
  router.get("/:publicUuid", validateLocationPublicUuidParam, getLocationByPublicUuid);

  return router;
}

export default createLocationsRouter();
