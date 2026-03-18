import express from "express";
import { getCurrentUser, requireAuth } from "../middlewares/auth.js";

const router = express.Router();

router.use(requireAuth);

router.get("/me", getCurrentUser);

export default router;
