import pool from "../config/db.js";
import { findUserById } from "../repositories/userRepo.js";

/**
 * If a timed suspension has expired, reactivate the account and clear restriction fields.
 */
export async function resolveUserAccountForAuth(user) {
  if (
    !user ||
    user.account_status !== "suspended" ||
    !user.account_status_expires_at
  ) {
    return user;
  }

  const expiresAt = new Date(user.account_status_expires_at);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt > new Date()) {
    return user;
  }

  await pool.execute(
    `
      UPDATE users
      SET
        account_status = 'active',
        account_status_reason = NULL,
        account_status_expires_at = NULL
      WHERE id = ?
        AND account_status = 'suspended'
        AND account_status_expires_at IS NOT NULL
        AND account_status_expires_at <= CURRENT_TIMESTAMP
    `,
    [user.id],
  );

  return findUserById(user.id);
}

export function computeSuspensionEndsAt(body) {
  if (body.accountStatus !== "suspended") {
    return null;
  }

  if (body.suspendedUntil) {
    return new Date(body.suspendedUntil);
  }

  if (body.suspensionDays != null) {
    const endsAt = new Date();
    endsAt.setDate(endsAt.getDate() + body.suspensionDays);
    return endsAt;
  }

  return null;
}
