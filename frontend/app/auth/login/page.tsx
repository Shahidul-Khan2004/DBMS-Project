"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { CheckCircle2 } from "lucide-react";
import { LoginCard } from "../../../components/auth/LoginCard";
import { LoginForm } from "../../../components/auth/LoginForm";
import {
  saveAuthSession,
  determineRole,
  getDashboardUrlFromRoleCodes,
} from "../../../lib/auth-store";
import type { LoginResponse } from "../../../types/auth";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";

export default function LoginPage() {
  const router = useRouter();
  const [loggedInUser, setLoggedInUser] = useState<LoginResponse | null>(null);

  const handleLoginSuccess = (data: LoginResponse) => {
    setLoggedInUser(data);
    const role = determineRole(data.authz?.roleCodes ?? []);
    saveAuthSession(data.accessToken, data.refreshToken, role);
    sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
  };

  useEffect(() => {
    if (!loggedInUser) return;

    const redirectUrl = getDashboardUrlFromRoleCodes(
      loggedInUser.authz?.roleCodes ?? [],
    );

    const timer = setTimeout(() => {
      router.push(redirectUrl);
    }, 200);

    return () => clearTimeout(timer);
  }, [loggedInUser, router]);

  if (loggedInUser) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200 px-4">
        <div className="w-full max-w-lg rounded-3xl border border-[#006747]/20 bg-zinc-200 p-8 shadow-lg shadow-[#002D62]/5">
          <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-[#006747] text-white">
            <CheckCircle2 className="h-7 w-7" aria-hidden />
          </div>
          <h1 className="text-2xl font-bold text-[#002D62]">
            Login successful
          </h1>
          <p className="mt-2 text-sm text-slate-600">
            Welcome back,{" "}
            <span className="font-medium text-slate-900">
              {loggedInUser.user.full_name}
            </span>
            . Redirecting to your dashboard.
          </p>

          <div className="mt-6 rounded-2xl border border-[#002D62]/10 bg-white p-4 text-sm text-slate-700">
            <p>
              <span className="font-medium">Email:</span>{" "}
              {loggedInUser.user.email}
            </p>
            <div className="mt-3">
              <Badge tone={loggedInUser.user.account_status}>
                {formatBadgeLabel(loggedInUser.user.account_status)}
              </Badge>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <LoginCard>
      <div className="space-y-6">
        <LoginForm onSuccess={handleLoginSuccess} />

        <div className="border-t border-[#002D62]/10 pt-4 text-center text-sm text-slate-600">
          Don&apos;t have an account?{" "}
          <Link
            href="/auth/register"
            className="font-semibold text-[#002D62] hover:text-[#006747]"
          >
            Register
          </Link>
        </div>
      </div>
    </LoginCard>
  );
}
