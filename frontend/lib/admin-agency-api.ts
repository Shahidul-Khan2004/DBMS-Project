import { apiGet, apiPatch, apiPost } from "@/lib/api";
import type {
  AdminActivateAgencyResponse,
  AdminAddRepresentativeResponse,
  AdminAgenciesListResponse,
  AdminAgencyDetailResponse,
  AdminAgencyRepresentativesResponse,
  AdminDeactivateAgencyResponse,
  AdminDeactivateMembershipResponse,
  AdminOnboardAgencyPayload,
  AdminOnboardAgencyResponse,
  AdminPatchAgencyPayload,
  AdminPatchAgencyResponse,
} from "@/types/admin-agency";

export type ListAdminAgenciesQuery = {
  limit?: number;
  offset?: number;
};

const DEFAULT_LIST_LIMIT = 20;

export async function listAdminAgencies(
  query: ListAdminAgenciesQuery = {},
): Promise<AdminAgenciesListResponse> {
  const search = new URLSearchParams({
    limit: String(query.limit ?? DEFAULT_LIST_LIMIT),
    offset: String(query.offset ?? 0),
  });

  const data = await apiGet<AdminAgenciesListResponse>(
    `/admin/agencies?${search.toString()}`,
  );

  return {
    ...data,
    agencies: data.agencies ?? [],
  };
}

export function getAdminAgency(agencyPublicUuid: string) {
  return apiGet<AdminAgencyDetailResponse>(
    `/admin/agencies/${encodeURIComponent(agencyPublicUuid)}`,
  );
}

export function updateAdminAgency(
  agencyPublicUuid: string,
  body: AdminPatchAgencyPayload,
) {
  return apiPatch<AdminPatchAgencyResponse>(
    `/admin/agencies/${encodeURIComponent(agencyPublicUuid)}`,
    body,
  );
}

export function activateAdminAgency(agencyPublicUuid: string) {
  return apiPatch<AdminActivateAgencyResponse>(
    `/admin/agencies/${encodeURIComponent(agencyPublicUuid)}/activate`,
    {},
  );
}

export function deactivateAdminAgency(agencyPublicUuid: string) {
  return apiPatch<AdminDeactivateAgencyResponse>(
    `/admin/agencies/${encodeURIComponent(agencyPublicUuid)}/deactivate`,
    {},
  );
}

export function onboardAgency(body: AdminOnboardAgencyPayload) {
  return apiPost<AdminOnboardAgencyResponse>("/admin/agencies/onboard", body);
}

export function listAgencyRepresentatives(agencyPublicUuid: string) {
  return apiGet<AdminAgencyRepresentativesResponse>(
    `/admin/agencies/${encodeURIComponent(agencyPublicUuid)}/representatives`,
  );
}

export function addAgencyRepresentative(
  agencyPublicUuid: string,
  userPublicUuid: string,
) {
  return apiPost<AdminAddRepresentativeResponse>(
    `/admin/agencies/${encodeURIComponent(agencyPublicUuid)}/representatives`,
    { user_public_uuid: userPublicUuid },
  );
}

export function deactivateAgencyMembership(membershipPublicUuid: string) {
  return apiPatch<AdminDeactivateMembershipResponse>(
    `/admin/agency-memberships/${encodeURIComponent(membershipPublicUuid)}/deactivate`,
    {},
  );
}
