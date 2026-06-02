import { apiJson, apiPost } from "@/lib/api";
import type { AssignUserRoleResponse } from "@/types/admin-agency";
import type { AuthzInfo, LoginResponse } from "@/types/auth";

export type MeResponse = {
  user: LoginResponse["user"];
  authz?: AuthzInfo;
};

export function getMe() {
  return apiJson<MeResponse>("/users/me");
}

export function assignUserRole(userPublicUuid: string, roleCode: string) {
  return apiPost<AssignUserRoleResponse>(
    `/users/${encodeURIComponent(userPublicUuid)}/roles`,
    { roleCode },
  );
}
