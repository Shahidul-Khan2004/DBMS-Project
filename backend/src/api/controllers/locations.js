import * as locationService from "../../services/locationService.js";
import BackendError from "../../lib/BackendError.js";

export async function postLocation(req, res) {
  const body = req.validated?.body ?? req.body;
  const location = await locationService.createLocationForActor(req.actorUserId, body);
  res.status(201).json({
    message: "Location created",
    location,
  });
}

export async function getMyLocations(req, res) {
  const locations = await locationService.listLocationsForActor(req.actorUserId);
  res.status(200).json({ locations });
}

export async function getLocationByPublicUuid(req, res) {
  const params = req.validated?.params ?? req.params;
  const location = await locationService.getLocationForActor(
    params.publicUuid,
    req.actorUserId,
    req.authz?.permissions ?? [],
  );
  if (!location) {
    throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
  }
  res.status(200).json({ location });
}
