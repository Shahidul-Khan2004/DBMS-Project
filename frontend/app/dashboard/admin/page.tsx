"use client";

import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { AdminOverviewWorkspace } from "@/components/admin/overview";
import { SystemAdminShell } from "@/components/admin/SystemAdminShell";
import { PageLoading } from "@/components/ui/StatusState";
import {
  ADMIN_DASHBOARD_SUBTITLE,
  ADMIN_DASHBOARD_TITLE,
} from "@/lib/admin-dashboard";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";

export default function AdminOverviewPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["system_admin"]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading admin console" />;
  }

  return (
    <DashboardLayout
      title={ADMIN_DASHBOARD_TITLE}
      subtitle={ADMIN_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
    >
      <SystemAdminShell cancelContentPadding={false}>
        <AdminOverviewWorkspace />
      </SystemAdminShell>
    </DashboardLayout>
  );
}
