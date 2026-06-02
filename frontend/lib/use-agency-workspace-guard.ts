"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ensureAuthSession } from "@/lib/api";
import { canAccessAgencyWorkspace } from "@/lib/agency-access";
import {
  clearAuthSession,
  getAuthSession,
  getAuthz,
  getDashboardUrl,
} from "@/lib/auth-store";

export function useAgencyWorkspaceGuard() {
  const router = useRouter();
  const [isChecking, setIsChecking] = useState(true);

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

      if (!canAccessAgencyWorkspace(authz, userRole)) {
        router.push(getDashboardUrl(userRole));
        return;
      }

      setIsChecking(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [router]);

  return isChecking;
}
