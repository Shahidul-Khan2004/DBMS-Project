import { apiGet } from "@/lib/api";
import type {
  AdministrativeAreaDetail,
  AdministrativeAreaDetailResponse,
} from "@/types/admin-area";

const detailCache = new Map<number, Promise<AdministrativeAreaDetail | null>>();

function parseAdminAreaDetail(
  value: AdministrativeAreaDetailResponse["adminArea"],
): AdministrativeAreaDetail | null {
  if (!value || typeof value.id !== "number") {
    return null;
  }

  const parseNode = (
    node: AdministrativeAreaDetail["division"],
  ): AdministrativeAreaDetail["division"] => {
    if (!node || typeof node.id !== "number") return null;
    return {
      id: node.id,
      name: String(node.name ?? ""),
      code: String(node.code ?? ""),
      areaType: String(node.areaType ?? ""),
    };
  };

  return {
    id: value.id,
    code: String(value.code ?? ""),
    name: String(value.name ?? ""),
    areaType: String(value.areaType ?? ""),
    hierarchyPath: String(value.hierarchyPath ?? "").trim(),
    division: parseNode(value.division),
    district: parseNode(value.district),
    upazila: parseNode(value.upazila),
    union: parseNode(value.union),
  };
}

export async function fetchAdministrativeAreaById(
  adminAreaId: number,
): Promise<AdministrativeAreaDetail | null> {
  if (!Number.isFinite(adminAreaId) || adminAreaId <= 0) {
    return null;
  }

  const cached = detailCache.get(adminAreaId);
  if (cached) {
    return cached;
  }

  const request = apiGet<AdministrativeAreaDetailResponse>(
    `/reference/administrative-areas/${adminAreaId}`,
  )
    .then((response) => parseAdminAreaDetail(response.adminArea))
    .catch(() => null);

  detailCache.set(adminAreaId, request);
  return request;
}
