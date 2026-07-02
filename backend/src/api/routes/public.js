import express from "express";
import {
  getPublicDisaster,
  getPublicDisasters,
} from "../controllers/publicDisasters.js";
import { getPublicDemoAccounts } from "../controllers/publicDemoAccounts.js";

export function createPublicRouter() {
  const router = express.Router();
  router.get("/demo-accounts", getPublicDemoAccounts);
  router.get("/disasters", getPublicDisasters);
  router.get("/disasters/:disasterPublicUuid", getPublicDisaster);
  return router;
}

export default createPublicRouter();
