import { searchAdministrativeAreas } from "../repositories/administrativeAreaSearchRepo.js";

export async function searchAdminAreas(params) {
  return searchAdministrativeAreas(params);
}
