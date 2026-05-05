"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession } from "@/lib/auth-store";
import type { LoginResponse } from "@/types/auth";

export default function DispatcherDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    if (sessionUser) {
      try {
        const parsedUser = JSON.parse(sessionUser);
        setUser(parsedUser);
        setIsLoading(false);
      } catch {
        router.push("/auth/login");
      }
    } else {
      router.push("/auth/login");
    }
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
      title="NIERS Dispatcher Console"
      subtitle="Manage incidents and classify reports"
      onLogout={handleLogout}
    >
      <div className="grid gap-6 md:grid-cols-3">
        {/* Dispatcher Info */}
        <Card className="shadow-md md:col-span-3">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Dispatcher Info
            </h2>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600">
              Name: <span className="font-medium">{user?.full_name}</span>
            </p>
            <p className="mt-2 text-sm text-gray-500">{user?.email}</p>
          </CardContent>
        </Card>

        {/* Incident Stats */}
        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Active Incidents
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">0</div>
            <p className="mt-2 text-sm text-gray-600">Emergency incidents</p>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Pending Intakes
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-yellow-600">0</div>
            <p className="mt-2 text-sm text-gray-600">To be classified</p>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Service Cases
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-600">0</div>
            <p className="mt-2 text-sm text-gray-600">Non-emergency cases</p>
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card className="shadow-md md:col-span-3">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">Actions</h2>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <Button className="flex-1">View All Intakes</Button>
              <Button variant="secondary" className="flex-1">
                View Incidents
              </Button>
              <Button variant="secondary" className="flex-1">
                View Service Cases
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
