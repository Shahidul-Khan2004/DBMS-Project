import type { UserRole } from "@/lib/auth-store";
import { agencyNationalDisasterDetailPath } from "@/lib/agency-national-disaster-routes";
import { nationalDisasterDetailPath } from "@/lib/admin-national-disaster-routes";
import { dispatcherNationalDisasterDetailPath } from "@/lib/dispatcher-national-disaster-routes";
import type { PublicDisaster } from "@/types/public-disaster";

export function formatDisasterDetail(value?: string | null) {
  if (!value) return null;
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

export function formatDisasterGuidance(value?: string | null) {
  const guidance = value?.trim().replace(/[/\s]+$/u, "");
  if (!guidance) return null;
  return /[.!?]$/u.test(guidance) ? guidance : `${guidance}.`;
}

export function buildDisasterHeadline(disaster: PublicDisaster) {
  const disasterType =
    formatDisasterDetail(disaster.disaster_type_name) ?? "Disaster";
  const severity =
    formatDisasterDetail(disaster.severity_level) ?? "Unspecified";
  const guidance = formatDisasterGuidance(disaster.public_guidance);

  return `NATIONAL DISASTER ALERT: ${disaster.title} — ${disasterType} emergency — Severity: ${severity}.${guidance ? ` ${guidance}` : ""}`;
}

export function buildDisasterSummaryLine(disaster: PublicDisaster) {
  const disasterType =
    formatDisasterDetail(disaster.disaster_type_name) ?? "Disaster";
  const severity =
    formatDisasterDetail(disaster.severity_level) ?? "Unspecified";

  return `${disaster.title} · ${disasterType} · Severity ${severity}`;
}

export function getOpsDisasterDetailPath(
  role: UserRole,
  disasterPublicUuid: string,
): string {
  switch (role) {
    case "dispatcher":
      return dispatcherNationalDisasterDetailPath(disasterPublicUuid);
    case "system_admin":
      return nationalDisasterDetailPath(disasterPublicUuid);
    case "agency_representative":
      return agencyNationalDisasterDetailPath(disasterPublicUuid);
    default:
      return "/#national-disaster";
  }
}
