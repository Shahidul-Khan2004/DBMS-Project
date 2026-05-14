"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { CheckCircle2 } from "lucide-react";
import { RegisterStepper } from "../../../components/auth/RegisterStepper";
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
    saveAuthSession(data.accessToken, data.refreshToken, role);
    sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
  };

  useEffect(() => {
    if (!registeredUser) return;

    const timer = setTimeout(() => {
      router.push("/dashboard/citizen");
    }, 1200);

    return () => clearTimeout(timer);
  }, [registeredUser, router]);

  if (registeredUser) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200 px-4">
        <div className="w-full max-w-lg rounded-3xl border border-[#006747]/20 bg-zinc-200 p-8 shadow-lg shadow-[#002D62]/5">
          <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-[#006747] text-white">
            <CheckCircle2 className="h-7 w-7" aria-hidden />
          </div>
          <h1 className="text-2xl font-bold text-[#002D62]">
            Registration complete
          </h1>
          <p className="mt-2 text-sm text-slate-600">
            Welcome,{" "}
            <span className="font-medium text-slate-900">
              {registeredUser.user.full_name}
            </span>
            . Redirecting to your dashboard.
          </p>

          <div className="mt-6 rounded-2xl border border-[#002D62]/10 bg-white p-4 text-sm text-slate-700">
            <p>
              <span className="font-medium">Email:</span>{" "}
              {registeredUser.user.email}
            </p>
            <p className="mt-2">
              <span className="font-medium">Phone:</span>{" "}
              {registeredUser.user.phone_number}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return <RegisterStepper onSuccess={handleRegistrationSuccess} />;
}
