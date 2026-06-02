"use client";

import type { ReactNode } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { SystemAdminShell } from "@/components/admin/SystemAdminShell";
import { PageLoading } from "@/components/ui/StatusState";
import {
  ADMIN_DASHBOARD_SUBTITLE,
  ADMIN_DASHBOARD_TITLE,
} from "@/lib/admin-dashboard";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";

type AdminDashboardPageProps = {
  children: ReactNode;
  loadingLabel: string;
  fillViewport?: boolean;
  scrollContent?: boolean;
};

export function AdminDashboardPage({
  children,
  loadingLabel,
  fillViewport = true,
  scrollContent = false,
}: AdminDashboardPageProps) {
  const router = useRouter();
  const isChecking = useAuthGuard(["system_admin"]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label={loadingLabel} />;
  }

  return (
    <DashboardLayout
      title={ADMIN_DASHBOARD_TITLE}
      subtitle={ADMIN_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName="flex min-h-0 flex-col lg:h-[calc(100vh-11.5rem)]"
    >
      <SystemAdminShell
        fillViewport={fillViewport}
        className={`flex min-h-0 flex-1 flex-col ${
          scrollContent
            ? "overflow-y-auto lg:min-h-0 lg:py-2"
            : "lg:overflow-hidden lg:min-h-0 lg:py-2"
        }`}
      >
        {children}
      </SystemAdminShell>
    </DashboardLayout>
  );
}
