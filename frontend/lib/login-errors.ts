import type { ApiError } from "@/lib/api";

export type LoginAccountStatusDetails = {
  accountStatus?: string;
  reason?: string | null;
  suspendedUntil?: string | null;
  remainingSeconds?: number | null;
};

export type LoginErrorDisplay = {
  title: string;
  description: string;
  details: string[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function parseAccountStatusDetails(details: unknown): LoginAccountStatusDetails {
  if (!isRecord(details)) return {};
  return {
    accountStatus:
      typeof details.accountStatus === "string" ? details.accountStatus : undefined,
    reason: typeof details.reason === "string" ? details.reason : null,
    suspendedUntil:
      typeof details.suspendedUntil === "string" ? details.suspendedUntil : null,
    remainingSeconds:
      typeof details.remainingSeconds === "number" ? details.remainingSeconds : null,
  };
}

export function formatRemainingSeconds(seconds: number): string {
  if (seconds <= 0) {
    return "Suspension period has ended";
  }

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  const parts: string[] = [];
  if (days > 0) {
    parts.push(`${days} ${days === 1 ? "day" : "days"}`);
  }
  if (hours > 0) {
    parts.push(`${hours} ${hours === 1 ? "hour" : "hours"}`);
  }
  if (parts.length === 0 && minutes > 0) {
    parts.push(`${minutes} ${minutes === 1 ? "minute" : "minutes"}`);
  }
  if (parts.length === 0) {
    return "Less than a minute";
  }

  return parts.join(" ");
}

function formatSuspendedUntilLabel(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function remainingFromSuspendedUntil(suspendedUntil: string): string | null {
  const until = new Date(suspendedUntil);
  if (Number.isNaN(until.getTime())) return null;
  const seconds = Math.floor((until.getTime() - Date.now()) / 1000);
  return formatRemainingSeconds(seconds);
}

export function formatLoginError(err: unknown): LoginErrorDisplay | null {
  if (!err || typeof err !== "object" || !("code" in err)) {
    return null;
  }

  const apiErr = err as ApiError;
  const details = parseAccountStatusDetails(apiErr.details);

  if (apiErr.code === "ACCOUNT_SUSPENDED") {
    const lines: string[] = [];
    if (details.remainingSeconds != null) {
      lines.push(`Suspension remaining: ${formatRemainingSeconds(details.remainingSeconds)}`);
    } else if (details.suspendedUntil) {
      const remaining = remainingFromSuspendedUntil(details.suspendedUntil);
      if (remaining) {
        lines.push(`Suspension remaining: ${remaining}`);
      }
    }
    if (details.suspendedUntil) {
      lines.push(`Suspended until: ${formatSuspendedUntilLabel(details.suspendedUntil)}`);
    }
    if (details.reason) {
      lines.push(`Reason: ${details.reason}`);
    }

    return {
      title: "Account suspended",
      description: "Your account has been suspended.",
      details: lines,
    };
  }

  if (apiErr.code === "ACCOUNT_DISABLED") {
    const lines: string[] = [];
    if (details.reason) {
      lines.push(`Reason: ${details.reason}`);
    }

    return {
      title: "Account disabled",
      description: "Your account has been disabled.",
      details: lines,
    };
  }

  if (apiErr.code === "ACCOUNT_PENDING_VERIFICATION") {
    return {
      title: "Account pending verification",
      description:
        "Your account is not active yet. Please verify your account or contact support.",
      details: [],
    };
  }

  return null;
}

export function formatLoginFallbackMessage(err: unknown): string {
  if (err instanceof Error && err.message) {
    return err.message;
  }
  return "Login failed. Please try again.";
}
