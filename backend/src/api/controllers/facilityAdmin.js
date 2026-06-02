import BackendError from "../../lib/BackendError.js";
import * as facilityService from "../../services/facilityAdminService.js";

export async function getFacilities(req, res) {
  const query = req.validated?.query ?? req.query;
  const facilities = await facilityService.listFacilities(query);
  res.status(200).json({ facilities });
}

export async function getFacility(req, res) {
  const { facilityPublicUuid } = req.params;
  const facility = await facilityService.getFacilityByPublicUuid(facilityPublicUuid);
  if (!facility) {
    throw new BackendError(404, "FACILITY_NOT_FOUND", "Facility not found");
  }
  res.status(200).json({ facility });
}

export async function postFacility(req, res) {
  const body = req.validated?.body ?? req.body;
  const facility = await facilityService.createFacility({
    actorUserId: req.actorUserId,
    facilityTypeCode: body.facilityTypeCode,
    name: body.name,
    facilityCode: body.facilityCode,
    location: body.location,
  });
  res.status(201).json({ facility });
}

export async function putFacilityCapabilities(req, res) {
  const { facilityPublicUuid } = req.params;
  const body = req.validated?.body ?? req.body;
  const facility = await facilityService.setFacilityCapabilities(
    facilityPublicUuid,
    body.capabilityCodes,
  );
  res.status(200).json({ facility });
}

export async function putFacilityDefaultCapacities(req, res) {
  const { facilityPublicUuid } = req.params;
  const body = req.validated?.body ?? req.body;
  const facility = await facilityService.setFacilityDefaultCapacities(
    facilityPublicUuid,
    body.capacities,
  );
  res.status(200).json({ facility });
}

export async function patchDeactivateFacility(req, res) {
  const { facilityPublicUuid } = req.validated?.params ?? req.params;
  const facility = await facilityService.deactivateFacility(facilityPublicUuid);
  res.status(200).json({
    message: "Facility deactivated",
    facility,
  });
}

export async function patchActivateFacility(req, res) {
  const { facilityPublicUuid } = req.validated?.params ?? req.params;
  const facility = await facilityService.activateFacility(facilityPublicUuid);
  res.status(200).json({
    message: "Facility activated",
    facility,
  });
}
