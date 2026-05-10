import express from "express";
import { postLocation } from "../controllers/locations.js";
import { requireAuth } from "../middlewares/auth.js";
import { validateCreateLocation } from "../validators/location.js";

const router = express.Router();

router.use(requireAuth);

router.post("/", validateCreateLocation, postLocation);

export default router;
