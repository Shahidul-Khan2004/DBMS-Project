import type { UserRole } from "@/lib/auth-store";
import type { AuthzInfo } from "@/types/auth";

export function hasDispatcherWorkspaceRole(userRole: UserRole): boolean {
  return userRole === "dispatcher" || userRole === "system_admin";
}

export function isSystemAdminOversight(userRole: UserRole): boolean {
  return userRole === "system_admin";
}

function hasDispatcherRoleCode(authz: AuthzInfo | null): boolean {
  const codes = authz?.roleCodes ?? [];
  return codes.includes("dispatcher") || codes.includes("system_admin");
}

export function canAccessDispatcherWorkspace(
  authz: AuthzInfo | null,
  userRole: UserRole,
): boolean {
  if (authz?.permissions?.includes("incident.classify")) {
    return true;
  }

  if (hasDispatcherRoleCode(authz)) {
    return true;
  }

  return hasDispatcherWorkspaceRole(userRole);
}

export function canAccessDispatcherServiceCases(
  authz: AuthzInfo | null,
  userRole: UserRole,
): boolean {
  if (authz?.permissions?.includes("case.respond")) {
    return true;
  }

  return canAccessDispatcherWorkspace(authz, userRole);
}

export function canAccessDispatcherIncidentMutate(
  authz: AuthzInfo | null,
  userRole: UserRole,
): boolean {
  const permissions = authz?.permissions ?? [];
  if (
    permissions.includes("incident.create") ||
    permissions.includes("incident.update_status")
  ) {
    return true;
  }

  return canAccessDispatcherWorkspace(authz, userRole);
}
