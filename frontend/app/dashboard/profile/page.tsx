"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { apiJson } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { LoginResponse } from "@/types/auth";

type MeResponse = {
  user: LoginResponse["user"];
};

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function ProfilePage() {
  const router = useRouter();
  const isChecking = useAuthGuard();
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (isChecking) return;

    async function loadProfile() {
      try {
        const data = await apiJson<MeResponse>("/users/me");
        setUser(data.user);
        sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load profile.");
      }
    }

    void loadProfile();
  }, [isChecking]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <div className="flex min-h-screen items-center justify-center">Loading...</div>;
  }

  return (
    <DashboardLayout
      title="Profile"
      subtitle="Account details from /users/me"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
        {error && <ErrorAlert message={error} />}

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">My Profile</h2>
          </CardHeader>
          <CardContent>
            {!user && !error ? (
              <LoadingSkeleton lines={5} />
            ) : user ? (
              <dl className="grid gap-4 sm:grid-cols-2">
                <div>
                  <dt className="text-sm font-medium text-gray-600">Name</dt>
                  <dd className="mt-1 text-sm text-gray-900">{user.full_name}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Status</dt>
                  <dd className="mt-1">
                    <Badge tone={user.account_status}>
                      {formatBadgeLabel(user.account_status)}
                    </Badge>
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Email</dt>
                  <dd className="mt-1 text-sm text-gray-900">{user.email}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Phone</dt>
                  <dd className="mt-1 text-sm text-gray-900">{user.phone_number}</dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-sm font-medium text-gray-600">User UUID</dt>
                  <dd className="mt-1 break-all text-sm text-gray-900">{user.id}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Created</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {formatDate(user.created_at)}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Updated</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {formatDate(user.updated_at)}
                  </dd>
                </div>
              </dl>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
