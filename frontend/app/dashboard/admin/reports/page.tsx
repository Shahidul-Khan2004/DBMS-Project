"use client";

import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { AdminReportsWorkspace } from "@/components/admin/reports";
import { SystemAdminShell } from "@/components/admin/SystemAdminShell";
import { PageLoading } from "@/components/ui/StatusState";
import {
  ADMIN_DASHBOARD_SUBTITLE,
  ADMIN_DASHBOARD_TITLE,
} from "@/lib/admin-dashboard";
import { OPS_DASHBOARD_CONTENT_CLASS } from "@/lib/dashboard-viewport";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";

export default function AdminReportsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["system_admin"]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading reports" />;
  }

  return (
    <DashboardLayout
      title={ADMIN_DASHBOARD_TITLE}
      subtitle={ADMIN_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName={OPS_DASHBOARD_CONTENT_CLASS}
    >
      <SystemAdminShell
        fillViewport
        cancelContentPadding={false}
        className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0 lg:py-2"
      >
        <AdminReportsWorkspace />
      </SystemAdminShell>
    </DashboardLayout>
  );
}
