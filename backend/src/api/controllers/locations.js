import * as locationService from "../../services/locationService.js";

export async function postLocation(req, res) {
  const body = req.validated?.body ?? req.body;
  const location = await locationService.createLocationForActor(req.actorUserId, body);
  res.status(201).json({
    message: "Location created",
    location,
  });
}
