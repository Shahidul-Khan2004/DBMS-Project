import { apiGet } from "@/lib/api";
import type { AdministrativeAreaSearchResponse } from "@/types/reference";

export type SearchAdministrativeAreasQuery = {
  areaType: "district" | "upazila";
  q: string;
  limit?: number;
};

export async function searchAdministrativeAreas(
  query: SearchAdministrativeAreasQuery,
): Promise<AdministrativeAreaSearchResponse> {
  const search = new URLSearchParams({
    areaType: query.areaType,
    q: query.q.trim(),
    limit: String(query.limit ?? 20),
  });

  const data = await apiGet<AdministrativeAreaSearchResponse>(
    `/reference/administrative-areas/search?${search.toString()}`,
  );

  return {
    ...data,
    areas: data.areas ?? [],
  };
}
