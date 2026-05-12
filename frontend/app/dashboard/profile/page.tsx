"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { PageLoading } from "@/components/ui/StatusState";
import { apiJson } from "@/lib/api";
import { clearAuthSession, getAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { AuthzInfo, LoginResponse } from "@/types/auth";

type MeResponse = {
  user: LoginResponse["user"];
  authz?: AuthzInfo;
};

function formatRoleLabel(value: string) {
  return value.replace(/_/g, " ");
}

export default function ProfilePage() {
  const router = useRouter();
  const isChecking = useAuthGuard();
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [authz, setAuthz] = useState<AuthzInfo | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (isChecking) return;

    async function loadProfile() {
      try {
        const data = await apiJson<MeResponse>("/users/me");
        setUser(data.user);
        setAuthz(data.authz ?? null);
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
    return <PageLoading label="Loading profile" />;
  }

  return (
    <DashboardLayout
      title="Profile"
      subtitle="Account details from /users/me"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-5xl space-y-6">
        {error && <ErrorAlert message={error} />}

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-[#002D62]">
              Identity and Status
            </h2>
          </CardHeader>
          <CardContent>
            {!user && !error ? (
              <LoadingSkeleton lines={5} />
            ) : user ? (
              <dl className="grid gap-4 sm:grid-cols-2">
                <div>
                  <dt className="text-sm font-medium text-gray-600">Full Name</dt>
                  <dd className="mt-1 text-sm font-semibold text-gray-900">
                    {user.full_name || "-"}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">
                    Account Status
                  </dt>
                  <dd className="mt-1">
                    <Badge tone={user.account_status}>
                      {formatBadgeLabel(user.account_status)}
                    </Badge>
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Email</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {user.email || "-"}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">
                    Phone Number
                  </dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {user.phone_number || "-"}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">
                    User Public UUID
                  </dt>
                  <dd className="mt-1 break-all text-sm text-gray-900">
                    {user.id}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Created</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {formatBangladeshTime(user.created_at)}
                  </dd>
                </div>
              </dl>
            ) : null}
          </CardContent>
        </Card>

        {user ? (
          <Card className="shadow-md">
            <CardHeader>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Role Information
              </h2>
            </CardHeader>
            <CardContent className="space-y-5">
              <div>
                <h3 className="text-sm font-semibold text-gray-700">Roles</h3>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(authz?.roleCodes?.length
                    ? authz.roleCodes
                    : [getAuthSession().userRole]
                  ).map((roleCode) => (
                    <Badge key={roleCode} tone="active">
                      {formatRoleLabel(roleCode)}
                    </Badge>
                  ))}
                </div>
              </div>

            </CardContent>
          </Card>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
