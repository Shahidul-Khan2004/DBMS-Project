import express from "express";
import {
  getPublicDisaster,
  getPublicDisasters,
} from "../controllers/publicDisasters.js";

export function createPublicRouter() {
  const router = express.Router();
  router.get("/disasters", getPublicDisasters);
  router.get("/disasters/:disasterPublicUuid", getPublicDisaster);
  return router;
}

export default createPublicRouter();
