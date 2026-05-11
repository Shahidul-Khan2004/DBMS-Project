"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  clearAuthSession,
  getAuthSession,
  getDashboardUrl,
  type UserRole,
} from "@/lib/auth-store";

export function useAuthGuard(allowedRoles?: UserRole[]) {
  const router = useRouter();
  const [isChecking, setIsChecking] = useState(true);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    const { accessToken, userRole } = getAuthSession();

    if (!sessionUser || !accessToken) {
      clearAuthSession();
      sessionStorage.removeItem("loggedInUser");
      router.push("/auth/login");
      return;
    }

    if (allowedRoles?.length && !allowedRoles.includes(userRole)) {
      router.push(getDashboardUrl(userRole));
      return;
    }

    setIsChecking(false);
  }, [allowedRoles, router]);

  return isChecking;
}
