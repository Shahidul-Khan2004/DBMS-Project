import * as adminAgencyRepo from "../repositories/adminAgencyRepo.js";
import { resolveGeoSortFromQuery } from "./geoSortService.js";

export async function adminListAgencies(query) {
  const { geoSort } = await resolveGeoSortFromQuery(query);
  return adminAgencyRepo.listAgencies({
    limit: query.limit ?? 20,
    offset: query.offset ?? 0,
    geoSort,
  });
}

export function adminGetAgency(agencyPublicUuid) {
  return adminAgencyRepo.getAgencyDetail(agencyPublicUuid);
}

export function adminPatchAgency(agencyPublicUuid, body, actorUserId) {
  return adminAgencyRepo.patchAgency(agencyPublicUuid, {
    ...body,
    actorUserId,
  });
}

export function adminDeactivateAgency(agencyPublicUuid) {
  return adminAgencyRepo.deactivateAgency(agencyPublicUuid);
}

export function adminActivateAgency(agencyPublicUuid, actorUserId) {
  return adminAgencyRepo.activateAgency(agencyPublicUuid, actorUserId);
}

export function adminOnboardAgency(body, actorUserId) {
  if (body.agency_public_uuid) {
    return adminAgencyRepo.onboardAgency({
      agencyPublicUuid: body.agency_public_uuid,
      userPublicUuid: body.user_public_uuid,
      actorUserId,
    });
  }

  return adminAgencyRepo.onboardAgency({
    agency: body.agency,
    userPublicUuid: body.user_public_uuid,
    actorUserId,
  });
}

export function adminLinkRepresentative(agencyPublicUuid, userPublicUuid, actorUserId) {
  return adminAgencyRepo.linkAgencyRepresentative(agencyPublicUuid, userPublicUuid, actorUserId);
}

export function adminListRepresentatives(agencyPublicUuid) {
  return adminAgencyRepo.listAgencyRepresentatives(agencyPublicUuid);
}

export function adminDeactivateMembership(membershipPublicUuid) {
  return adminAgencyRepo.deactivateMembership(membershipPublicUuid);
}
