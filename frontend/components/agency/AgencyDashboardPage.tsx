"use client";

import type { ReactNode } from "react";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { AgencyOpsShell } from "@/components/agency/AgencyOpsShell";
import { getAgencyMe } from "@/lib/agency-api";
import { mapAgencyAccessError } from "@/lib/agency-api-errors";
import {
  AGENCY_WORKSPACE_TITLE_FALLBACK,
} from "@/lib/agency-dashboard";
import {
  getAgencyOperationsSubtitle,
  getAgencyWorkspaceTitle,
} from "@/lib/agency-microcopy";
import { OPS_DASHBOARD_CONTENT_CLASS } from "@/lib/dashboard-viewport";
import { clearAuthSession } from "@/lib/auth-store";
import { useAgencyWorkspaceGuard } from "@/lib/use-agency-workspace-guard";
import { PageLoading } from "@/components/ui/StatusState";

export function AgencyDashboardPage({
  children,
  shellClassName = "",
}: {
  children: ReactNode;
  shellClassName?: string;
}) {
  const router = useRouter();
  const isChecking = useAgencyWorkspaceGuard();
  const [headerTitle, setHeaderTitle] = useState(AGENCY_WORKSPACE_TITLE_FALLBACK);
  const [headerSubtitle, setHeaderSubtitle] = useState("Loading agency access...");
  const loadHeader = useCallback(async () => {
    try {
      const data = await getAgencyMe();
      setHeaderTitle(getAgencyWorkspaceTitle(data.agency.name));
      setHeaderSubtitle(
        getAgencyOperationsSubtitle(data.agency.agency_type_code, false, false),
      );
    } catch (err) {
      setHeaderTitle(AGENCY_WORKSPACE_TITLE_FALLBACK);
      setHeaderSubtitle(getAgencyOperationsSubtitle(null, false, true));
      if (process.env.NODE_ENV === "development") {
        console.error("Agency header load failed", mapAgencyAccessError(err));
      }
    }
  }, []);

  useEffect(() => {
    if (isChecking) return;
    void loadHeader();
  }, [isChecking, loadHeader]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading agency workspace" />;
  }

  return (
    <DashboardLayout
      title={headerTitle}
      subtitle={headerSubtitle}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName={OPS_DASHBOARD_CONTENT_CLASS}
    >
      <AgencyOpsShell
        cancelContentPadding={false}
        className={`flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0 ${shellClassName}`.trim()}
      >
        {children}
      </AgencyOpsShell>
    </DashboardLayout>
  );
}
