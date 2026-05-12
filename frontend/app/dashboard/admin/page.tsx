"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { PageLoading } from "@/components/ui/StatusState";
import { RoleAssignmentForm } from "@/components/admin/RoleAssignmentForm";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { LoginResponse } from "@/types/auth";

function readSessionUser() {
  if (typeof window === "undefined") return null;

  const sessionUser = sessionStorage.getItem("loggedInUser");
  if (!sessionUser) return null;

  try {
    return JSON.parse(sessionUser) as LoginResponse["user"];
  } catch {
    return null;
  }
}

export default function AdminDashboard() {
  const router = useRouter();
  const isCheckingAuth = useAuthGuard(["system_admin"]);
  const user = readSessionUser();

  useEffect(() => {
    if (isCheckingAuth) return;

    if (!user) {
      router.push("/auth/login");
    }
  }, [isCheckingAuth, router, user]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isCheckingAuth || !user) {
    return <PageLoading label="Loading admin console" />;
  }

  return (
    <DashboardLayout
      title="NIERS Admin Console"
      subtitle="System administration and user management"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-screen-xl space-y-6">
        <Card className="shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <ShieldAlert className="h-5 w-5" aria-hidden />
              </div>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Current Admin
              </h2>
            </div>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-4 sm:grid-cols-2">
              <div>
                <dt className="text-sm font-medium text-gray-600">Email</dt>
                <dd className="mt-1 break-words text-sm text-gray-900">
                  {user?.email || "-"}
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <RoleAssignmentForm />
      </div>
    </DashboardLayout>
  );
}
