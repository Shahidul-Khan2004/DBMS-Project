"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { ensureAuthSession } from "@/lib/api";
import {
  clearAuthSession,
  getAuthSession,
  getDashboardUrl,
  type UserRole,
} from "@/lib/auth-store";

export function useAuthGuard(allowedRoles?: UserRole[]) {
  const router = useRouter();
  const [isChecking, setIsChecking] = useState(true);
  const allowedRolesKey = allowedRoles?.join("|") ?? "";
  const allowedRoleSet = useMemo(
    () =>
      new Set(
        allowedRolesKey ? (allowedRolesKey.split("|") as UserRole[]) : [],
      ),
    [allowedRolesKey],
  );

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const accessToken = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");
      const { userRole } = getAuthSession();

      if (cancelled) return;

      if (!sessionUser || !accessToken) {
        clearAuthSession();
        sessionStorage.removeItem("loggedInUser");
        router.push("/auth/login");
        return;
      }

      if (allowedRoleSet.size > 0 && !allowedRoleSet.has(userRole)) {
        router.push(getDashboardUrl(userRole));
        return;
      }

      setIsChecking(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [allowedRoleSet, router]);

  return isChecking;
}
