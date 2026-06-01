"use client";

import { Suspense, use } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DisasterDetailWorkspace } from "@/components/admin/disasters";
import { SystemAdminShell } from "@/components/admin/SystemAdminShell";
import { PageLoading } from "@/components/ui/StatusState";
import {
  ADMIN_DASHBOARD_SUBTITLE,
  ADMIN_DASHBOARD_TITLE,
} from "@/lib/admin-dashboard";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";

function DisasterDetailPageContent({
  params,
}: {
  params: Promise<{ disasterPublicUuid: string }>;
}) {
  const { disasterPublicUuid } = use(params);
  const router = useRouter();
  const isChecking = useAuthGuard(["system_admin"]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading disaster dashboard" />;
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
        fillViewport
        className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0 lg:py-2"
      >
        <DisasterDetailWorkspace disasterPublicUuid={disasterPublicUuid} />
      </SystemAdminShell>
    </DashboardLayout>
  );
}

export default function AdminDisasterDetailPage({
  params,
}: {
  params: Promise<{ disasterPublicUuid: string }>;
}) {
  return (
    <Suspense fallback={<PageLoading label="Loading disaster dashboard" />}>
      <DisasterDetailPageContent params={params} />
    </Suspense>
  );
}
