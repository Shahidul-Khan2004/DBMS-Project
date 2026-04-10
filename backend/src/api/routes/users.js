import express from "express";
import { requireAuth } from "../middlewares/auth.js";
import { getCurrentUser } from "../controllers/auth.js";

const router = express.Router();

router.use(requireAuth);

router.get("/me", getCurrentUser);

export default router;
