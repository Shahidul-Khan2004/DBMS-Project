import * as adminAgencyService from "../../services/adminAgencyService.js";

export async function postAdminOnboardAgency(req, res) {
  const body = req.validated?.body ?? req.body;
  const result = await adminAgencyService.adminOnboardAgency(body, req.actorUserId);
  res.status(201).json({
    message: body.user_public_uuid
      ? "Agency representative onboarded"
      : "Agency onboarded",
    ...result,
  });
}

export async function getAdminAgencies(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await adminAgencyService.adminListAgencies(query);
  res.status(200).json(result);
}

export async function getAdminAgency(req, res) {
  const { agencyPublicUuid } = req.validated?.params ?? req.params;
  const result = await adminAgencyService.adminGetAgency(agencyPublicUuid);
  res.status(200).json(result);
}

export async function patchAdminAgency(req, res) {
  const { agencyPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const agency = await adminAgencyService.adminPatchAgency(
    agencyPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(200).json({ agency });
}

export async function patchAdminDeactivateAgency(req, res) {
  const { agencyPublicUuid } = req.validated?.params ?? req.params;
  const result = await adminAgencyService.adminDeactivateAgency(agencyPublicUuid);
  res.status(200).json({
    message: "Agency deactivated",
    ...result,
  });
}

export async function patchAdminActivateAgency(req, res) {
  const { agencyPublicUuid } = req.validated?.params ?? req.params;
  const result = await adminAgencyService.adminActivateAgency(
    agencyPublicUuid,
    req.actorUserId,
  );
  res.status(200).json({
    message: "Agency activated",
    ...result,
  });
}

export async function postAdminAgencyRepresentative(req, res) {
  const { agencyPublicUuid } = req.validated?.params ?? req.params;
  const { user_public_uuid: userPublicUuid } = req.validated?.body ?? req.body;
  const representative = await adminAgencyService.adminLinkRepresentative(
    agencyPublicUuid,
    userPublicUuid,
    req.actorUserId,
  );
  res.status(201).json({
    message: "Agency representative linked",
    representative,
  });
}

export async function getAdminAgencyRepresentatives(req, res) {
  const { agencyPublicUuid } = req.validated?.params ?? req.params;
  const result = await adminAgencyService.adminListRepresentatives(agencyPublicUuid);
  res.status(200).json(result);
}

export async function patchAdminDeactivateMembership(req, res) {
  const { membershipPublicUuid } = req.validated?.params ?? req.params;
  const membership = await adminAgencyService.adminDeactivateMembership(membershipPublicUuid);
  res.status(200).json({
    message: "Agency membership deactivated",
    membership,
  });
}
