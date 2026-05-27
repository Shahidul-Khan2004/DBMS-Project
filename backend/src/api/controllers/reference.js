import * as referenceService from "../../services/referenceService.js";

export async function getAdministrativeAreaSearch(req, res) {
  const query = req.validated?.query ?? req.query;
  const areas = await referenceService.searchAdminAreas({
    areaType: query.areaType,
    q: query.q,
    limit: query.limit,
  });
  res.status(200).json({ areas });
}
