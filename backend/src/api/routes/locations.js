import express from "express";
import {
  getLocationByPublicUuid,
  getMyLocations,
  postLocation,
} from "../controllers/locations.js";
import { requireAuth } from "../middlewares/auth.js";
import {
  validateCreateLocation,
  validateLocationPublicUuidParam,
} from "../validators/location.js";

const router = express.Router();

router.use(requireAuth);

router.post("/", validateCreateLocation, postLocation);
router.get("/my", getMyLocations);
router.get("/:publicUuid", validateLocationPublicUuidParam, getLocationByPublicUuid);

export default router;
