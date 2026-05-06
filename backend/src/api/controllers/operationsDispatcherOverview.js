import * as dispatcherOverviewService from "../../services/dispatcherOverviewService.js";

export async function getOperationsDispatcherOverview(req, res) {
  const payload = await dispatcherOverviewService.getDispatcherOverviewPayload();
  res.status(200).json(payload);
}
