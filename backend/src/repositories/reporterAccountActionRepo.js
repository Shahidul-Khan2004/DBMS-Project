import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import pool, { query } from "../config/db.js";
import { insertAuditLog } from "../lib/auditLog.js";
import { toMySqlDateTimeOrNull } from "../lib/mysqlDateTime.js";

function formatAccountActionRow(row) {
  return {
    public_uuid: row.public_uuid,
    action_type: row.action_type,
    previous_account_status: row.previous_account_status,
    new_account_status: row.new_account_status,
    reason: row.reason,
    suspension_ends_at: row.suspension_ends_at ?? null,
    created_at: row.created_at,
    action_by: row.action_by_public_uuid
      ? {
          public_uuid: row.action_by_public_uuid,
          full_name: row.action_by_full_name,
        }
      : undefined,
  };
}

export async function insertReporterAccountAction(conn, params) {
  const publicUuid = randomUUID();
  const suspensionEndsAtSql = toMySqlDateTimeOrNull(params.suspensionEndsAt);
  await conn.execute(
    `
      INSERT INTO reporter_account_actions (
        public_uuid,
        target_user_id,
        action_by_user_id,
        action_type,
        previous_account_status,
        new_account_status,
        reason,
        suspension_ends_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      publicUuid,
      params.targetUserId,
      params.actionByUserId,
      params.actionType,
      params.previousAccountStatus ?? null,
      params.newAccountStatus ?? null,
      params.reason,
      suspensionEndsAtSql,
    ],
  );

  const [rows] = await conn.execute(
    `
      SELECT
        raa.public_uuid,
        raa.action_type,
        raa.previous_account_status,
        raa.new_account_status,
        raa.reason,
        raa.suspension_ends_at,
        raa.created_at,
        ab.public_uuid AS action_by_public_uuid,
        abp.full_name AS action_by_full_name
      FROM reporter_account_actions raa
      INNER JOIN users ab ON ab.id = raa.action_by_user_id
      LEFT JOIN user_profiles abp ON abp.user_id = ab.id
      WHERE raa.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );

  return formatAccountActionRow(rows[0]);
}

export async function listAccountActionsForUser(targetUserId, limit = 20) {
  const capped = Math.min(Math.max(Number(limit) || 20, 1), 100);
  const { rows } = await query(
    `
      SELECT
        raa.public_uuid,
        raa.action_type,
        raa.previous_account_status,
        raa.new_account_status,
        raa.reason,
        raa.suspension_ends_at,
        raa.created_at,
        ab.public_uuid AS action_by_public_uuid,
        abp.full_name AS action_by_full_name
      FROM reporter_account_actions raa
      INNER JOIN users ab ON ab.id = raa.action_by_user_id
      LEFT JOIN user_profiles abp ON abp.user_id = ab.id
      WHERE raa.target_user_id = ?
      ORDER BY raa.created_at DESC
      LIMIT ?
    `,
    [targetUserId, capped],
  );

  return rows.map(formatAccountActionRow);
}

export async function updateUserAccountStatusInTransaction(
  conn,
  { targetUserId, newStatus, actorUserId, reason, suspensionEndsAt = null },
) {
  const [userRows] = await conn.execute(
    `
      SELECT u.id, u.public_uuid, u.email, u.account_status, u.account_status_reason, u.account_status_expires_at, up.full_name, up.phone_number
      FROM users u
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE u.id = ?
      FOR UPDATE
    `,
    [targetUserId],
  );

  const user = userRows[0];
  if (!user) {
    throw new BackendError(404, "USER_NOT_FOUND", "User not found");
  }

  const previousStatus = user.account_status;
  if (previousStatus === newStatus) {
    throw new BackendError(
      409,
      "ACCOUNT_STATUS_UNCHANGED",
      "Account status is already set to the requested value",
    );
  }

  let actionType;
  if (newStatus === "active") {
    actionType = "reactivate";
  } else if (newStatus === "suspended") {
    actionType = "suspension";
  } else if (newStatus === "disabled") {
    actionType = "disable";
  } else {
    throw new BackendError(422, "VALIDATION_ERROR", "Invalid account status");
  }

  const expiresAtSql = toMySqlDateTimeOrNull(
    newStatus === "suspended" ? suspensionEndsAt : null,
  );

  await conn.execute(
    `
      UPDATE users
      SET
        account_status = ?,
        account_status_reason = ?,
        account_status_expires_at = ?
      WHERE id = ?
    `,
    [
      newStatus,
      newStatus === "active" ? null : reason,
      newStatus === "suspended" ? expiresAtSql : null,
      targetUserId,
    ],
  );

  const accountAction = await insertReporterAccountAction(conn, {
    targetUserId,
    actionByUserId: actorUserId,
    actionType,
    previousAccountStatus: previousStatus,
    newAccountStatus: newStatus,
    reason,
    suspensionEndsAt: newStatus === "suspended" ? suspensionEndsAt : null,
  });

  await insertAuditLog(conn, {
    actorUserId,
    action: "user.account_status_updated",
    entityType: "user",
    entityId: targetUserId,
    detailsJson: {
      previous_account_status: previousStatus,
      new_account_status: newStatus,
      account_action_public_uuid: accountAction.public_uuid,
      reason,
      suspension_ends_at: suspensionEndsAt,
    },
  });

  return {
    user: {
      public_uuid: user.public_uuid,
      email: user.email,
      full_name: user.full_name,
      phone_number: user.phone_number,
      account_status: newStatus,
      is_active: newStatus === "active",
      account_status_reason: newStatus === "active" ? null : reason,
      account_status_expires_at: newStatus === "suspended" ? expiresAtSql : null,
    },
    accountAction,
  };
}

export async function recordWarningOrNoteAction(
  conn,
  { targetUserId, actorUserId, actionType, reason },
) {
  const [userRows] = await conn.execute(
    `SELECT id, account_status FROM users WHERE id = ? LIMIT 1`,
    [targetUserId],
  );

  if (!userRows[0]) {
    throw new BackendError(404, "USER_NOT_FOUND", "User not found");
  }

  const currentStatus = userRows[0].account_status;
  const accountAction = await insertReporterAccountAction(conn, {
    targetUserId,
    actionByUserId: actorUserId,
    actionType,
    previousAccountStatus: currentStatus,
    newAccountStatus: currentStatus,
    reason,
  });

  await insertAuditLog(conn, {
    actorUserId,
    action: `reporter.${actionType}_recorded`,
    entityType: "user",
    entityId: targetUserId,
    detailsJson: {
      account_action_public_uuid: accountAction.public_uuid,
      reason,
    },
  });

  return accountAction;
}

export async function withReporterAccountTransaction(work) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await work(conn);
    await conn.commit();
    return result;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}
