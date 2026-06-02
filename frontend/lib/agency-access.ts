import type { UserRole } from "@/lib/auth-store";
import type { AuthzInfo } from "@/types/auth";

export function hasAgencyRepresentativeRole(userRole: UserRole): boolean {
  return userRole === "agency_representative";
}

function hasAgencyPermission(authz: AuthzInfo | null): boolean {
  const permissions = authz?.permissions ?? [];
  return (
    permissions.includes("agency.view_own") ||
    permissions.includes("dispatch.view_own_agency")
  );
}

function hasAgencyRepresentativeRoleCode(authz: AuthzInfo | null): boolean {
  const codes = authz?.roleCodes ?? [];
  return codes.includes("agency_representative");
}

export function canAccessAgencyWorkspace(
  authz: AuthzInfo | null,
  userRole: UserRole,
): boolean {
  if (hasAgencyPermission(authz)) {
    return true;
  }

  if (hasAgencyRepresentativeRoleCode(authz)) {
    return true;
  }

  return hasAgencyRepresentativeRole(userRole);
}
