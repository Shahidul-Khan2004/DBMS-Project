import BackendError from "../lib/BackendError.js";
import { findUserByPublicUuid } from "../repositories/userRepo.js";
import {
  findReporterRiskByPublicUuid,
  getReporterRiskSummaryCounts,
  listRecentReportsForReporter,
  listReporterRisks,
  resolveReporterUserIdByPublicUuid,
} from "../repositories/reporterRiskRepo.js";
import { listAccountActionsForUser } from "../repositories/reporterAccountActionRepo.js";
import {
  recordWarningOrNoteAction,
  updateUserAccountStatusInTransaction,
  withReporterAccountTransaction,
} from "../repositories/reporterAccountActionRepo.js";
import { computeSuspensionEndsAt } from "./userAccountStatusService.js";

export async function adminListReporterRisks(query) {
  return listReporterRisks(query);
}

export async function adminGetReporterRiskSummary() {
  return getReporterRiskSummaryCounts();
}

export async function adminGetReporterRiskDetail(userPublicUuid) {
  const reporterRisk = await findReporterRiskByPublicUuid(userPublicUuid);
  const userId = await resolveReporterUserIdByPublicUuid(userPublicUuid);
  if (!userId) {
    throw new BackendError(404, "USER_NOT_FOUND", "Reporter not found");
  }

  const [recentReports, accountActions] = await Promise.all([
    listRecentReportsForReporter(userId),
    listAccountActionsForUser(userId),
  ]);

  return {
    reporter_risk: reporterRisk,
    recent_reports: recentReports,
    account_actions: accountActions,
  };
}

export async function adminUpdateUserAccountStatus(
  userPublicUuid,
  body,
  actorUserId,
  actorPublicUuid,
) {
  if (userPublicUuid === actorPublicUuid) {
    throw new BackendError(
      403,
      "FORBIDDEN",
      "You cannot change your own account status",
    );
  }

  const targetUser = await findUserByPublicUuid(userPublicUuid);
  if (!targetUser) {
    throw new BackendError(404, "USER_NOT_FOUND", "User not found");
  }

  const suspensionEndsAt = computeSuspensionEndsAt(body);

  return withReporterAccountTransaction((conn) =>
    updateUserAccountStatusInTransaction(conn, {
      targetUserId: targetUser.id,
      newStatus: body.accountStatus,
      actorUserId,
      reason: body.reason,
      suspensionEndsAt,
    }),
  );
}

export async function adminRecordReporterAction(
  userPublicUuid,
  body,
  actorUserId,
) {
  const targetUser = await findUserByPublicUuid(userPublicUuid);
  if (!targetUser) {
    throw new BackendError(404, "USER_NOT_FOUND", "User not found");
  }

  const accountAction = await withReporterAccountTransaction((conn) =>
    recordWarningOrNoteAction(conn, {
      targetUserId: targetUser.id,
      actorUserId,
      actionType: body.actionType,
      reason: body.reason,
    }),
  );

  return {
    message: "Reporter account action recorded",
    account_action: {
      public_uuid: accountAction.public_uuid,
      action_type: accountAction.action_type,
      reason: accountAction.reason,
      created_at: accountAction.created_at,
    },
  };
}
