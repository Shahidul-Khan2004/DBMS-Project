"use client";

import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DisasterCommandLinkReportsWorkspace } from "@/components/dispatcher/disasters/DisasterCommandLinkReportsWorkspace";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { PageLoading } from "@/components/ui/StatusState";
import { clearAuthSession } from "@/lib/auth-store";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";

export default function DispatcherDisasterLinkReportsPage() {
  const router = useRouter();
  const params = useParams();
  const isChecking = useDispatcherWorkspaceGuard();

  const disasterPublicUuid =
    typeof params.uuid === "string" ? params.uuid : "";

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading disaster command" />;
  }

  return (
    <DashboardLayout
      title={DISPATCHER_DASHBOARD_TITLE}
      subtitle={DISPATCHER_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName="flex min-h-0 flex-col lg:h-[calc(100vh-11.5rem)]"
    >
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0 lg:py-2">
        <DisasterCommandLinkReportsWorkspace
          disasterPublicUuid={disasterPublicUuid}
        />
      </DispatcherOpsShell>
    </DashboardLayout>
  );
}
