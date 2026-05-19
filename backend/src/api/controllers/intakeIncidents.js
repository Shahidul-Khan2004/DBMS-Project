import * as incidentOperationsService from "../../services/incidentOperationsService.js";

export async function getMyIncidents(req, res) {
  const result = await incidentOperationsService.listMyIncidents(req.user.id);
  res.status(200).json(result);
}
