"use client";

import { startTransition, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { ArchiveWorkspace, useArchiveList } from "@/components/dispatcher/archive";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { useActiveIncidentCardLocations } from "@/components/dispatcher/incidents/useActiveIncidentCardLocations";
import { Button } from "@/components/ui/Button";
import { PageLoading } from "@/components/ui/StatusState";
import { ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";

export default function DispatcherArchivePage() {
  const router = useRouter();
  const [isLoadingSession, setIsLoadingSession] = useState(true);

  const {
    recordType,
    finalState,
    setRecordType,
    setFinalState,
    isLoading,
    error,
    partialError,
    incidentSourceRows,
    incidentItems,
    incidentUuids,
    serviceCases,
    refresh,
    loadMore,
    retryPartialStream,
    incidentHasMore,
    serviceCaseHasMore,
  } = useArchiveList(!isLoadingSession);

  const { getCardLocation, resetCardLocations } = useActiveIncidentCardLocations(
    recordType === "incidents" && !(isLoading && incidentItems.length === 0)
      ? incidentUuids
      : [],
  );

  const handleRefresh = () => {
    if (recordType === "incidents") {
      resetCardLocations();
    }
    refresh();
  };

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const accessToken = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");

      if (cancelled) return;

      if (!sessionUser || !accessToken) {
        sessionStorage.removeItem("loggedInUser");
        clearAuthSession();
        startTransition(() => {
          router.replace("/auth/login");
        });
        return;
      }
      setIsLoadingSession(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [router]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isLoadingSession) {
    return <PageLoading label="Loading archive" />;
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
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0">
        <div className="flex min-h-0 flex-1 flex-col gap-4 lg:overflow-hidden">
          <header className="flex shrink-0 flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold text-slate-900">Archive</h2>
              <p className="mt-0.5 text-sm text-slate-600">
                Review completed, closed, cancelled, and escalated dispatcher records.
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="shrink-0"
              onClick={handleRefresh}
              disabled={isLoading}
            >
              {isLoading ? "Refreshing…" : "Refresh"}
            </Button>
          </header>

          <ArchiveWorkspace
            className="min-h-0 flex-1"
            recordType={recordType}
            finalState={finalState}
            onRecordTypeChange={setRecordType}
            onFinalStateChange={setFinalState}
            isLoading={isLoading}
            error={error}
            partialError={partialError}
            incidentItems={incidentItems}
            incidentSourceRows={incidentSourceRows}
            getCardLocation={getCardLocation}
            serviceCases={serviceCases}
            incidentHasMore={incidentHasMore}
            serviceCaseHasMore={serviceCaseHasMore}
            onLoadMore={loadMore}
            onRetry={handleRefresh}
            onRetryPartialStream={retryPartialStream}
          />
        </div>
      </DispatcherOpsShell>
    </DashboardLayout>
  );
}
