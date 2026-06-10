"use client";

import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DispatcherDisastersWorkspace } from "@/components/dispatcher/disasters/DispatcherDisastersWorkspace";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { PageLoading } from "@/components/ui/StatusState";
import { OPS_DASHBOARD_CONTENT_CLASS } from "@/lib/dashboard-viewport";
import { clearAuthSession } from "@/lib/auth-store";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";

export default function DispatcherDisastersPage() {
  const router = useRouter();
  const isChecking = useDispatcherWorkspaceGuard();

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading national disasters" />;
  }

  return (
    <DashboardLayout
      title={DISPATCHER_DASHBOARD_TITLE}
      subtitle={DISPATCHER_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName={OPS_DASHBOARD_CONTENT_CLASS}
    >
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0 lg:py-2">
        <DispatcherDisastersWorkspace />
      </DispatcherOpsShell>
    </DashboardLayout>
  );
}
