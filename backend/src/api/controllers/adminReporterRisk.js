import * as reporterRiskAdminService from "../../services/reporterRiskAdminService.js";

export async function getAdminReporterRisks(req, res) {
  const query = req.validated?.query ?? req.query;
  const result = await reporterRiskAdminService.adminListReporterRisks(query);
  res.status(200).json(result);
}

export async function getAdminReporterRiskDetail(req, res) {
  const { userPublicUuid } = req.validated?.params ?? req.params;
  const result = await reporterRiskAdminService.adminGetReporterRiskDetail(
    userPublicUuid,
  );
  res.status(200).json(result);
}

export async function patchAdminUserAccountStatus(req, res) {
  const { userPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const actorPublicUuid = req.user?.id ?? req.auth?.sub;

  const { user, accountAction } =
    await reporterRiskAdminService.adminUpdateUserAccountStatus(
      userPublicUuid,
      body,
      req.actorUserId,
      actorPublicUuid,
    );

  res.status(200).json({
    message: "User account status updated",
    user,
    account_action: {
      public_uuid: accountAction.public_uuid,
      action_type: accountAction.action_type,
      reason: accountAction.reason,
      suspension_ends_at: accountAction.suspension_ends_at ?? null,
      created_at: accountAction.created_at,
    },
  });
}

export async function postAdminReporterAction(req, res) {
  const { userPublicUuid } = req.validated?.params ?? req.params;
  const body = req.validated?.body ?? req.body;
  const result = await reporterRiskAdminService.adminRecordReporterAction(
    userPublicUuid,
    body,
    req.actorUserId,
  );
  res.status(201).json(result);
}
