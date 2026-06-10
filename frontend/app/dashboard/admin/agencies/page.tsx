"use client";

import { Suspense } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { AgenciesWorkspace } from "@/components/admin/agencies";
import { SystemAdminShell } from "@/components/admin/SystemAdminShell";
import { PageLoading } from "@/components/ui/StatusState";
import {
  ADMIN_DASHBOARD_SUBTITLE,
  ADMIN_DASHBOARD_TITLE,
} from "@/lib/admin-dashboard";
import { OPS_DASHBOARD_CONTENT_CLASS } from "@/lib/dashboard-viewport";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";

function AgenciesPageContent() {
  const router = useRouter();
  const isChecking = useAuthGuard(["system_admin"]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading agencies" />;
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
        <AgenciesWorkspace />
      </SystemAdminShell>
    </DashboardLayout>
  );
}

export default function AdminAgenciesPage() {
  return (
    <Suspense fallback={<PageLoading label="Loading agencies" />}>
      <AgenciesPageContent />
    </Suspense>
  );
}
