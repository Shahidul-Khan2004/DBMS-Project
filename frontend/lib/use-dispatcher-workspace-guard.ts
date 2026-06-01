"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { ensureAuthSession } from "@/lib/api";
import {
  canAccessDispatcherIncidentMutate,
  canAccessDispatcherServiceCases,
  canAccessDispatcherWorkspace,
} from "@/lib/dispatcher-access";
import {
  clearAuthSession,
  getAuthSession,
  getAuthz,
  getDashboardUrl,
} from "@/lib/auth-store";

export type DispatcherWorkspaceAccess =
  | "workspace"
  | "serviceCases"
  | "incidentMutate";

function canAccess(
  access: DispatcherWorkspaceAccess,
  authz: ReturnType<typeof getAuthz>,
  userRole: ReturnType<typeof getAuthSession>["userRole"],
): boolean {
  switch (access) {
    case "serviceCases":
      return canAccessDispatcherServiceCases(authz, userRole);
    case "incidentMutate":
      return canAccessDispatcherIncidentMutate(authz, userRole);
    case "workspace":
    default:
      return canAccessDispatcherWorkspace(authz, userRole);
  }
}

export function useDispatcherWorkspaceGuard(
  access: DispatcherWorkspaceAccess = "workspace",
) {
  const router = useRouter();
  const [isChecking, setIsChecking] = useState(true);
  const accessKey = access;

  const accessMode = useMemo(
    () => accessKey as DispatcherWorkspaceAccess,
    [accessKey],
  );

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const accessToken = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");
      const { userRole } = getAuthSession();
      const authz = getAuthz();

      if (cancelled) return;

      if (!sessionUser || !accessToken) {
        clearAuthSession();
        sessionStorage.removeItem("loggedInUser");
        router.push("/auth/login");
        return;
      }

      if (!canAccess(accessMode, authz, userRole)) {
        router.push(getDashboardUrl(userRole));
        return;
      }

      setIsChecking(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [accessMode, router]);

  return isChecking;
}
