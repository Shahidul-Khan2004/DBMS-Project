import express from "express";
import {
  requireAuth as defaultRequireAuth,
  requirePermission,
} from "../middlewares/auth.js";
import { requireAgencyContext as defaultRequireAgencyContext } from "../middlewares/agencyContext.js";
import {
  getAgencyDisasterDetail,
  getAgencyDisasterIncidents,
  getAgencyDisasterReliefHubs,
  getAgencyDisasterReliefRequests,
  getAgencyDisasterShelters,
  getAgencyDisasters,
  getAgencyDispatches,
  getAgencyIncidents,
  getAgencyIncidentNotes,
  getAgencyMe,
  getAgencyResponseLogs,
  getAgencyUnits,
  patchAgencyDeactivateUnit,
  patchAgencyDispatchStatus,
  patchAgencyUnit,
  patchAgencyUnitStatus,
  postAgencyDisasterReliefRequest,
  postAgencyReliefHubStockReceipt,
  postAgencyResponseLog,
  postAgencyShelterOccupancy,
  postAgencyUnit,
} from "../controllers/agency.js";
import {
  validateAgencyCreateReliefRequest,
  validateAgencyCreateResponseLog,
  validateAgencyHubActivationParam,
  validateAgencyCreateUnit,
  validateAgencyDisasterUuidParam,
  validateAgencyDispatchUuidParam,
  validateAgencyIncidentUuidParam,
  validateAgencyListQuery,
  validateAgencyOccupancySnapshot,
  validateAgencyShelterActivationParam,
  validateAgencyStockReceipt,
  validateAgencyUnitsListQuery,
  validateAgencyPatchDispatchStatus,
  validateAgencyPatchUnit,
  validateAgencyPatchUnitStatus,
  validateAgencyUnitUuidParam,
} from "../validators/agency.js";

export function createAgencyRouter({
  requireAuth = defaultRequireAuth,
  requireAgencyContext = defaultRequireAgencyContext,
} = {}) {
  const router = express.Router();

  router.use(requireAuth);
  router.use(requireAgencyContext);

  router.get("/me", requirePermission("agency.view_own"), getAgencyMe);
  router.get(
    "/disasters",
    requirePermission("disaster.read"),
    validateAgencyListQuery,
    getAgencyDisasters,
  );
  router.get(
    "/disasters/:disasterPublicUuid",
    requirePermission("disaster.read"),
    validateAgencyDisasterUuidParam,
    getAgencyDisasterDetail,
  );
  router.get(
    "/disasters/:disasterPublicUuid/shelters",
    requirePermission("disaster.read"),
    validateAgencyDisasterUuidParam,
    getAgencyDisasterShelters,
  );
  router.get(
    "/disasters/:disasterPublicUuid/relief-hubs",
    requirePermission("disaster.read"),
    validateAgencyDisasterUuidParam,
    getAgencyDisasterReliefHubs,
  );
  router.post(
    "/disasters/:disasterPublicUuid/shelters/:shelterActivationPublicUuid/occupancy",
    requirePermission("shelter.record_occupancy_own"),
    validateAgencyShelterActivationParam,
    validateAgencyOccupancySnapshot,
    postAgencyShelterOccupancy,
  );
  router.get(
    "/disasters/:disasterPublicUuid/relief-requests",
    requirePermission("disaster.read"),
    validateAgencyDisasterUuidParam,
    getAgencyDisasterReliefRequests,
  );
  router.post(
    "/disasters/:disasterPublicUuid/relief-requests",
    requirePermission("relief.request_own_shelter"),
    validateAgencyDisasterUuidParam,
    validateAgencyCreateReliefRequest,
    postAgencyDisasterReliefRequest,
  );
  router.post(
    "/disasters/:disasterPublicUuid/relief-hubs/:hubActivationPublicUuid/stock-receipts",
    requirePermission("relief.manage_inventory_own"),
    validateAgencyHubActivationParam,
    validateAgencyStockReceipt,
    postAgencyReliefHubStockReceipt,
  );
  router.get(
    "/disasters/:disasterPublicUuid/incidents",
    requirePermission("disaster.read"),
    validateAgencyDisasterUuidParam,
    getAgencyDisasterIncidents,
  );
  router.get(
    "/incidents",
    requirePermission("dispatch.view_own_agency"),
    validateAgencyListQuery,
    getAgencyIncidents,
  );
  router.get(
    "/dispatches",
    requirePermission("dispatch.view_own_agency"),
    validateAgencyListQuery,
    getAgencyDispatches,
  );
  router.patch(
    "/dispatches/:dispatchPublicUuid/status",
    requirePermission("dispatch.update_own_agency"),
    validateAgencyDispatchUuidParam,
    validateAgencyPatchDispatchStatus,
    patchAgencyDispatchStatus,
  );
  router.get(
    "/units",
    requirePermission("agency.view_own"),
    validateAgencyUnitsListQuery,
    getAgencyUnits,
  );
  router.post(
    "/units",
    requirePermission("agency.manage_own_units"),
    validateAgencyCreateUnit,
    postAgencyUnit,
  );
  router.patch(
    "/units/:unitPublicUuid",
    requirePermission("agency.manage_own_units"),
    validateAgencyUnitUuidParam,
    validateAgencyPatchUnit,
    patchAgencyUnit,
  );
  router.patch(
    "/units/:unitPublicUuid/deactivate",
    requirePermission("agency.manage_own_units"),
    validateAgencyUnitUuidParam,
    patchAgencyDeactivateUnit,
  );
  router.patch(
    "/units/:unitPublicUuid/status",
    requirePermission("agency.manage_own_units"),
    validateAgencyUnitUuidParam,
    validateAgencyPatchUnitStatus,
    patchAgencyUnitStatus,
  );
  router.get(
    "/incidents/:incidentPublicUuid/notes",
    requirePermission("dispatch.view_own_agency"),
    validateAgencyIncidentUuidParam,
    validateAgencyListQuery,
    getAgencyIncidentNotes,
  );
  router.get(
    "/incidents/:incidentPublicUuid/response-logs",
    requirePermission("dispatch.view_own_agency"),
    validateAgencyIncidentUuidParam,
    validateAgencyListQuery,
    getAgencyResponseLogs,
  );
  router.post(
    "/incidents/:incidentPublicUuid/response-logs",
    requirePermission("response_log.create_own_agency"),
    validateAgencyIncidentUuidParam,
    validateAgencyCreateResponseLog,
    postAgencyResponseLog,
  );

  return router;
}

export default createAgencyRouter();
