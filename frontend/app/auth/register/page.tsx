"use client";

import Link from "next/link";
import { RegistrationCard } from "../../../components/auth/RegistrationCard";
import { RegisterForm } from "../../../components/auth/RegisterForm";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { saveAuthSession, determineRole } from "../../../lib/auth-store";
import type { RegisterResponse } from "../../../types/auth";

export default function RegisterPage() {
  const router = useRouter();
  const [registeredUser, setRegisteredUser] = useState<RegisterResponse | null>(
    null,
  );

  const handleRegistrationSuccess = (data: RegisterResponse) => {
    setRegisteredUser(data);
    const role = determineRole(data.authz?.roleCodes ?? []);
    // Store auth session for new user
    saveAuthSession(data.accessToken, data.refreshToken, role);
    // Store user in session for dashboard
    sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
  };

  useEffect(() => {
    if (registeredUser) {
      // New users are citizens, redirect to citizen dashboard after 2 seconds
      const timer = setTimeout(() => {
        router.push("/dashboard/citizen");
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [registeredUser, router]);

  if (registeredUser) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-emerald-50 to-slate-50 px-4">
        <div className="w-full max-w-lg rounded-xl border border-emerald-200 bg-white p-8 shadow-lg">
          <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100">
            <span className="text-2xl">✓</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">
            Registration complete
          </h1>
          <p className="mt-2 text-sm text-slate-600">
            Welcome,{" "}
            <span className="font-medium text-slate-900">
              {registeredUser.user.full_name}
            </span>
            . Redirecting to your dashboard...
          </p>

          <div className="mt-6 rounded-lg bg-slate-50 p-4 text-sm text-slate-700">
            <p>
              <span className="font-medium">Email:</span>{" "}
              {registeredUser.user.email}
            </p>
            <p>
              <span className="font-medium">Phone:</span>{" "}
              {registeredUser.user.phone_number}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <RegistrationCard>
      <div className="space-y-6">
        <RegisterForm onSuccess={handleRegistrationSuccess} />

        <div className="border-t border-slate-200 pt-4 text-center text-sm text-slate-600">
          Already have an account?{" "}
          <Link
            href="/auth/login"
            className="font-semibold text-blue-600 hover:text-blue-700"
          >
            Login
          </Link>
        </div>
      </div>
    </RegistrationCard>
  );
}
