import BackendError from "./BackendError.js";

function toIsoOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function remainingSecondsFromExpiry(expiresAt) {
  if (!expiresAt) return null;
  const until = new Date(expiresAt);
  if (Number.isNaN(until.getTime())) return null;
  return Math.max(0, Math.floor((until.getTime() - Date.now()) / 1000));
}

export function assertUserCanLogin(user) {
  const status = user.account_status;

  if (status === "active") {
    return;
  }

  if (status === "suspended") {
    const suspendedUntil = toIsoOrNull(user.account_status_expires_at);
    throw new BackendError(403, "ACCOUNT_SUSPENDED", "Account suspended", {
      accountStatus: "suspended",
      reason: user.account_status_reason ?? null,
      suspendedUntil,
      remainingSeconds: remainingSecondsFromExpiry(user.account_status_expires_at),
    });
  }

  if (status === "disabled") {
    throw new BackendError(403, "ACCOUNT_DISABLED", "Account disabled", {
      accountStatus: "disabled",
      reason: user.account_status_reason ?? null,
    });
  }

  if (status === "pending_verification") {
    throw new BackendError(
      403,
      "ACCOUNT_PENDING_VERIFICATION",
      "Account pending verification",
      {
        accountStatus: "pending_verification",
      },
    );
  }

  throw new BackendError(403, "USER_INACTIVE", "User account is inactive");
}
