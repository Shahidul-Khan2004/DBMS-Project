"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { RoleAssignmentForm } from "@/components/admin/RoleAssignmentForm";
import { clearAuthSession } from "@/lib/auth-store";
import type { LoginResponse } from "@/types/auth";

export default function AdminDashboard() {
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
      title="NIERS Admin Console"
      subtitle="System administration and user management"
      onLogout={handleLogout}
    >
      <div className="grid gap-6 md:grid-cols-3">
        {/* Admin Info */}
        <Card className="shadow-md md:col-span-3">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              System Admin
            </h2>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600">
              Name: <span className="font-medium">{user?.full_name}</span>
            </p>
            <p className="mt-2 text-sm text-gray-500">User ID: {user?.id}</p>
            <p className="mt-2 text-sm text-gray-500">{user?.email}</p>
            <p className="mt-2 text-sm text-green-600 font-medium">
              Full administrative access
            </p>
          </CardContent>
        </Card>

        {/* System Stats */}
        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">Total Users</h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-600">0</div>
            <p className="mt-2 text-sm text-gray-600">Registered users</p>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Active Roles
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-purple-600">0</div>
            <p className="mt-2 text-sm text-gray-600">Dispatchers assigned</p>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              System Health
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-sm">
              <p className="text-green-600 font-medium">Operational</p>
              <p className="mt-1 text-gray-600">All services running</p>
            </div>
          </CardContent>
        </Card>

        {/* Admin Actions */}
        <Card className="shadow-md md:col-span-3">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">Management</h2>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2">
              <Button>Manage Users</Button>
              <Button>Assign Roles</Button>
              <Button variant="secondary">View System Logs</Button>
              <Button variant="secondary">System Settings</Button>
            </div>
          </CardContent>
        </Card>

        <div className="md:col-span-3">
          <RoleAssignmentForm />
        </div>
      </div>
    </DashboardLayout>
  );
}
