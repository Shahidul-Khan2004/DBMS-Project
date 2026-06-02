import * as incidentOperationsService from "../../services/incidentOperationsService.js";

export async function getMyIncidents(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await incidentOperationsService.listMyIncidents(req.user.id, query);
  res.status(200).json(result);
}
