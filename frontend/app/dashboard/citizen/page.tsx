"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession } from "@/lib/auth-store";
import type { LoginResponse } from "@/types/auth";
import type { IntakeReportStatsResponse } from "@/types/intake";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

export default function CitizenDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [stats, setStats] = useState({
    totalReports: 0,
    pendingReports: 0,
    resolvedReports: 0,
  });
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const loadDashboard = async () => {
      const sessionUser = sessionStorage.getItem("loggedInUser");
      const accessToken = localStorage.getItem("accessToken");

      if (!sessionUser || !accessToken) {
        router.push("/auth/login");
        return;
      }

      try {
        const parsedUser = JSON.parse(sessionUser);
        setUser(parsedUser);

        const response = await fetch(`${API_BASE}/intake/reports/my/stats`, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        });

        if (response.ok) {
          const data = (await response.json()) as IntakeReportStatsResponse;
          setStats(data.stats);
        }
      } catch {
        router.push("/auth/login");
        return;
      } finally {
        setIsLoading(false);
      }
    };

    loadDashboard();
  }, [router]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    );
  }

  return (
    <DashboardLayout
      title="NIERS Citizen Portal"
      subtitle="Report incidents and emergencies"
      onLogout={handleLogout}
    >
      <div className="grid gap-6 md:grid-cols-2">
        {/* Welcome Card */}
        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">Welcome</h2>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600">
              Hello, <span className="font-medium">{user?.full_name}</span>
            </p>
            <p className="mt-2 text-sm text-gray-500">User ID: {user?.id}</p>
            <p className="mt-2 text-sm text-gray-500">{user?.email}</p>
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">Actions</h2>
          </CardHeader>
          <CardContent>
            <Button
              fullWidth
              className="mb-3"
              onClick={() => router.push("/dashboard/citizen/report-new")}
            >
              Report New Incident
            </Button>
            <Button
              variant="secondary"
              fullWidth
              onClick={() => router.push("/dashboard/citizen/reports")}
            >
              View My Reports
            </Button>
          </CardContent>
        </Card>

        {/* Incident Stats */}
        <Card className="shadow-md md:col-span-2">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Your Reports
            </h2>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="rounded-lg bg-blue-50 p-4 text-center">
                <div className="text-2xl font-bold text-blue-600">
                  {stats.totalReports}
                </div>
                <p className="text-sm text-gray-600">Total Reports</p>
              </div>
              <div className="rounded-lg bg-yellow-50 p-4 text-center">
                <div className="text-2xl font-bold text-yellow-600">
                  {stats.pendingReports}
                </div>
                <p className="text-sm text-gray-600">Pending</p>
              </div>
              <div className="rounded-lg bg-green-50 p-4 text-center">
                <div className="text-2xl font-bold text-green-600">
                  {stats.resolvedReports}
                </div>
                <p className="text-sm text-gray-600">Resolved</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
