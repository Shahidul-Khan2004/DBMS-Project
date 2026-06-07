import cors from "cors";
import express from "express";
import healthRouter from "./api/routes/health.js";
import authRouter from "./api/routes/auth.js";
import { createUsersRouter } from "./api/routes/users.js";
import { createIntakeRouter } from "./api/routes/intake.js";
import { createOperationsRouter } from "./api/routes/operations.js";
import { createLocationsRouter } from "./api/routes/locations.js";
import { createNotificationsRouter } from "./api/routes/notifications.js";
import { createAdminRouter } from "./api/routes/admin.js";
import { createAdminReporterRiskRouter } from "./api/routes/adminReporterRisk.js";
import { createAgencyRouter } from "./api/routes/agency.js";
import { createPublicRouter } from "./api/routes/public.js";
import { createReferenceRouter } from "./api/routes/reference.js";
import { createDisastersRouter } from "./api/routes/disasters.js";
import { createFacilitiesRouter } from "./api/routes/facilities.js";
import { errorHandler, notFound } from "./api/middlewares/error.js";
import { requireAuth as defaultRequireAuth } from "./api/middlewares/auth.js";
import { requireAgencyContext as defaultRequireAgencyContext } from "./api/middlewares/agencyContext.js";

/**
 * @param {object} [options]
 * @param {import("express").RequestHandler} [options.requireAuth]
 * @param {import("express").RequestHandler} [options.requireAgencyContext]
 */
export function createApp(options = {}) {
  const requireAuth = options.requireAuth ?? defaultRequireAuth;
  const requireAgencyContext = options.requireAgencyContext ?? defaultRequireAgencyContext;

  const app = express();

  app.use(
    cors({
      origin: "http://localhost:3000",
    }),
  );
  app.use(express.json());

  app.use("/", healthRouter);
  app.use("/auth", authRouter);
  app.use("/users", createUsersRouter({ requireAuth }));
  app.use("/intake", createIntakeRouter({ requireAuth }));
  app.use("/operations", createOperationsRouter({ requireAuth }));
  app.use("/locations", createLocationsRouter({ requireAuth }));
  app.use("/notifications", createNotificationsRouter({ requireAuth }));
  app.use("/public", createPublicRouter());
  app.use("/reference", createReferenceRouter({ requireAuth }));
  app.use("/operations/disasters", createDisastersRouter({ requireAuth }));
  app.use("/admin/facilities", createFacilitiesRouter({ requireAuth }));
  app.use("/admin", createAdminReporterRiskRouter({ requireAuth }));
  app.use("/admin", createAdminRouter({ requireAuth }));
  app.use("/agency", createAgencyRouter({ requireAuth, requireAgencyContext }));

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
