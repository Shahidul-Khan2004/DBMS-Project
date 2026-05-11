"use client";

import Link from "next/link";
import { LoginCard } from "../../../components/auth/LoginCard";
import { LoginForm } from "../../../components/auth/LoginForm";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  saveAuthSession,
  determineRole,
  getDashboardUrlFromRoleCodes,
} from "../../../lib/auth-store";
import type { LoginResponse } from "../../../types/auth";

export default function LoginPage() {
  const router = useRouter();
  const [loggedInUser, setLoggedInUser] = useState<LoginResponse | null>(null);

  const handleLoginSuccess = (data: LoginResponse) => {
    setLoggedInUser(data);
    const role = determineRole(data.authz?.roleCodes ?? []);
    // Store auth session with correct role
    saveAuthSession(data.accessToken, data.refreshToken, role);
    // Store user in session for dashboard
    sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
  };

  useEffect(() => {
    if (loggedInUser) {
      const redirectUrl = getDashboardUrlFromRoleCodes(
        loggedInUser.authz?.roleCodes ?? [],
      );

      // Auto-redirect after 2 seconds
      const timer = setTimeout(() => {
        router.push(redirectUrl);
      }, 200);
      return () => clearTimeout(timer);
    }
  }, [loggedInUser, router]);

  if (loggedInUser) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-emerald-50 to-slate-50 px-4">
        <div className="w-full max-w-lg rounded-xl border border-emerald-200 bg-white p-8 shadow-lg">
          <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 text-2xl">
            ✓
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Login successful
          </h1>
          <p className="mt-2 text-sm text-slate-600">
            Welcome back,{" "}
            <span className="font-medium text-slate-900">
              {loggedInUser.user.full_name}
            </span>
            . Redirecting to your dashboard...
          </p>

          <div className="mt-6 rounded-lg bg-slate-50 p-4 text-sm text-slate-700">
            <p>
              <span className="font-medium">Email:</span>{" "}
              {loggedInUser.user.email}
            </p>
            <p>
              <span className="font-medium">Status:</span>{" "}
              {loggedInUser.user.account_status}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <LoginCard>
      <div className="space-y-6">
        <LoginForm onSuccess={handleLoginSuccess} />

        <div className="border-t border-slate-200 pt-4 text-center text-sm text-slate-600">
          Don’t have an account?{" "}
          <Link
            href="/auth/register"
            className="font-semibold text-blue-600 hover:text-blue-700"
          >
            Register
          </Link>
        </div>
      </div>
    </LoginCard>
  );
}
