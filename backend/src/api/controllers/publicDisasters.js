import BackendError from "../../lib/BackendError.js";
import * as disasterService from "../../services/disasterOperationsService.js";

export async function getPublicDisasters(_req, res) {
  const disasters = await disasterService.listPublicDisasters();
  res.status(200).json({ disasters });
}

export async function getPublicDisaster(req, res) {
  const { disasterPublicUuid } = req.params;
  const disaster = await disasterService.getPublicDisasterSummary(disasterPublicUuid);
  if (!disaster) {
    throw new BackendError(404, "DISASTER_NOT_PUBLIC", "Disaster summary is not publicly available");
  }
  res.status(200).json({ disaster });
}
