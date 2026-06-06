import express from "express";
import {
  deleteLinkIncident,
  getCandidateIncidents,
  getDisaster,
  getDisasters,
  getLinkedIncidents,
  patchAffectedAreaAssessment,
  patchDisasterStatus,
  postAffectedAreas,
  postApproveReliefRequest,
  postDeclarationAmendment,
  postDeactivateReliefHub,
  postDeactivateShelter,
  postDisaster,
  postInitialDeclaration,
  postLinkIncident,
  postManualReliefHub,
  postManualShelter,
  postRejectReliefRequest,
  postReliefDistribution,
  postReliefHubManagingAgency,
  postReliefRequest,
  postResponsibility,
  postRevokeResponsibility,
  postShelterManagingAgency,
  postShelterOccupancy,
  postStockReceipt,
} from "../controllers/disasterOperations.js";
import {
  requireAuth as defaultRequireAuth,
  requireAnyPermission,
  requirePermission,
} from "../middlewares/auth.js";
import {
  validateAddAffectedAreas,
  validateActivationDeactivation,
  validateAffectedAreaAssessment,
  validateAssignResponsibility,
  validateCreateDisaster,
  validateCreateDistribution,
  validateCreateReliefRequest,
  validateDeclarationAmendment,
  validateDisasterStatusPatch,
  validateDisasterUuidParam,
  validateInitialDeclaration,
  validateLinkIncident,
  validateManualHubActivation,
  validateManualShelterActivation,
  validateOccupancySnapshot,
  validateReliefHubManagingAgency,
  validateReliefRequestAction,
  validateRevokeResponsibility,
  validateShelterManagingAgency,
  validateStockReceipt,
  validateUnlinkIncident,
} from "../validators/disaster.js";
import { validateOperationsDisasterDetailGeoQuery } from "../validators/geoSort.js";
import validate from "../validators/validator.js";
import { z } from "zod";

const uuid = z.string().uuid();

const validateAffectedAreaUuidParam = validate(
  "affectedAreaUuidParam",
  z.object({
    disasterPublicUuid: uuid,
    affectedAreaPublicUuid: uuid,
  }),
  "params",
);

const validateIncidentUuidParam = validate(
  "incidentUuidParam",
  z.object({ disasterPublicUuid: uuid, incidentPublicUuid: uuid }),
  "params",
);

const validateShelterActivationParam = validate(
  "shelterActivationParam",
  z.object({
    disasterPublicUuid: uuid,
    shelterActivationPublicUuid: uuid,
  }),
  "params",
);

const validateHubActivationParam = validate(
  "hubActivationParam",
  z.object({
    disasterPublicUuid: uuid,
    hubActivationPublicUuid: uuid,
  }),
  "params",
);

const validateReliefRequestParam = validate(
  "reliefRequestParam",
  z.object({ reliefRequestPublicUuid: uuid }),
  "params",
);

export function createDisastersRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();
  router.use(requireAuth);

  router.post("/", requirePermission("disaster.create"), validateCreateDisaster, postDisaster);
  router.get(
    "/",
    requirePermission("disaster.read"),
    getDisasters,
  );
  router.get(
    "/:disasterPublicUuid",
    requirePermission("disaster.read"),
    validateDisasterUuidParam,
    validateOperationsDisasterDetailGeoQuery,
    getDisaster,
  );
  router.post(
    "/:disasterPublicUuid/status",
    requirePermission("disaster.update_status"),
    validateDisasterUuidParam,
    validateDisasterStatusPatch,
    patchDisasterStatus,
  );

  router.post(
    "/:disasterPublicUuid/affected-areas",
    requirePermission("disaster.manage_affected_areas"),
    validateDisasterUuidParam,
    validateAddAffectedAreas,
    postAffectedAreas,
  );
  router.patch(
    "/:disasterPublicUuid/affected-areas/:affectedAreaPublicUuid",
    requirePermission("disaster.manage_affected_areas"),
    validateAffectedAreaUuidParam,
    validateAffectedAreaAssessment,
    patchAffectedAreaAssessment,
  );

  router.post(
    "/:disasterPublicUuid/responsibilities",
    requirePermission("disaster.manage_responsibilities"),
    validateDisasterUuidParam,
    validateAssignResponsibility,
    postResponsibility,
  );
  router.post(
    "/:disasterPublicUuid/responsibilities/revoke",
    requirePermission("disaster.manage_responsibilities"),
    validateDisasterUuidParam,
    validateRevokeResponsibility,
    postRevokeResponsibility,
  );

  router.post(
    "/:disasterPublicUuid/declarations/initial",
    requirePermission("disaster.declare"),
    validateDisasterUuidParam,
    validateInitialDeclaration,
    postInitialDeclaration,
  );
  router.post(
    "/:disasterPublicUuid/declarations/amendments",
    requirePermission("disaster.declare"),
    validateDisasterUuidParam,
    validateDeclarationAmendment,
    postDeclarationAmendment,
  );

  router.get(
    "/:disasterPublicUuid/incidents/candidates",
    requirePermission("disaster.link_incidents"),
    validateDisasterUuidParam,
    getCandidateIncidents,
  );
  router.get(
    "/:disasterPublicUuid/incidents",
    requirePermission("disaster.read"),
    validateDisasterUuidParam,
    getLinkedIncidents,
  );
  router.post(
    "/:disasterPublicUuid/incidents",
    requirePermission("disaster.link_incidents"),
    validateDisasterUuidParam,
    validateLinkIncident,
    postLinkIncident,
  );
  router.delete(
    "/:disasterPublicUuid/incidents/:incidentPublicUuid",
    requireAnyPermission("disaster.link_incidents", "disaster.update_status"),
    validateIncidentUuidParam,
    validateUnlinkIncident,
    deleteLinkIncident,
  );

  router.post(
    "/:disasterPublicUuid/shelters",
    requirePermission("shelter.manage"),
    validateDisasterUuidParam,
    validateManualShelterActivation,
    postManualShelter,
  );
  router.post(
    "/:disasterPublicUuid/shelters/:shelterActivationPublicUuid/managing-agency",
    requirePermission("shelter.manage"),
    validateShelterActivationParam,
    validateShelterManagingAgency,
    postShelterManagingAgency,
  );
  router.post(
    "/:disasterPublicUuid/shelters/:shelterActivationPublicUuid/occupancy",
    requireAnyPermission("shelter.record_occupancy", "shelter.record_occupancy_own"),
    validateShelterActivationParam,
    validateOccupancySnapshot,
    postShelterOccupancy,
  );
  router.post(
    "/:disasterPublicUuid/shelters/:shelterActivationPublicUuid/deactivate",
    requirePermission("shelter.manage"),
    validateShelterActivationParam,
    validateActivationDeactivation,
    postDeactivateShelter,
  );

  router.post(
    "/:disasterPublicUuid/relief-hubs",
    requirePermission("shelter.manage"),
    validateDisasterUuidParam,
    validateManualHubActivation,
    postManualReliefHub,
  );
  router.post(
    "/:disasterPublicUuid/relief-hubs/:hubActivationPublicUuid/managing-agency",
    requirePermission("shelter.manage"),
    validateHubActivationParam,
    validateReliefHubManagingAgency,
    postReliefHubManagingAgency,
  );
  router.post(
    "/:disasterPublicUuid/relief-hubs/:hubActivationPublicUuid/stock-receipts",
    requirePermission("relief.manage_inventory"),
    validateHubActivationParam,
    validateStockReceipt,
    postStockReceipt,
  );
  router.post(
    "/:disasterPublicUuid/relief-hubs/:hubActivationPublicUuid/deactivate",
    requirePermission("shelter.manage"),
    validateHubActivationParam,
    validateActivationDeactivation,
    postDeactivateReliefHub,
  );

  router.post(
    "/:disasterPublicUuid/relief-requests",
    requireAnyPermission("relief.manage_requests", "relief.request_own_shelter"),
    validateDisasterUuidParam,
    validateCreateReliefRequest,
    postReliefRequest,
  );
  router.post(
    "/relief-requests/:reliefRequestPublicUuid/approve",
    requirePermission("relief.manage_requests"),
    validateReliefRequestParam,
    validateReliefRequestAction,
    postApproveReliefRequest,
  );
  router.post(
    "/relief-requests/:reliefRequestPublicUuid/reject",
    requirePermission("relief.manage_requests"),
    validateReliefRequestParam,
    validateReliefRequestAction,
    postRejectReliefRequest,
  );
  router.post(
    "/:disasterPublicUuid/relief-distributions",
    requirePermission("relief.distribute"),
    validateDisasterUuidParam,
    validateCreateDistribution,
    postReliefDistribution,
  );

  return router;
}

export default createDisastersRouter();
