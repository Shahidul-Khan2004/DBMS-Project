"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { ActiveIncidentsList } from "@/components/dispatcher/incidents/ActiveIncidentsList";
import { ActiveIncidentsToolbar } from "@/components/dispatcher/incidents/ActiveIncidentsToolbar";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { filterActiveIncidents } from "@/components/dispatcher/incidents/filterActiveIncidents";
import { filterNonTerminalOperationsIncidents } from "@/components/dispatcher/incidents/filterNonTerminalOperationsIncidents";
import { mapOperationsIncidentToActiveListItem } from "@/components/dispatcher/incidents/mapActiveIncidentListItem";
import type {
  ActiveIncidentListItem,
  ActiveIncidentsDateFilter,
  ActiveIncidentsStatusFilter,
} from "@/components/dispatcher/incidents/types";
import { useActiveIncidentCardLocations } from "@/components/dispatcher/incidents/useActiveIncidentCardLocations";
import { Button } from "@/components/ui/Button";
import { PageLoading } from "@/components/ui/StatusState";
import { ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { getOperationsIncidents } from "@/lib/operations-intake-triage";

const LIST_LIMIT = 50;
const LIST_OFFSET = 0;

export default function ActiveIncidentsPage() {
  const router = useRouter();
  const isChecking = useDispatcherWorkspaceGuard();
  const [incidents, setIncidents] = useState<ActiveIncidentListItem[]>([]);
  const [isLoadingIncidents, setIsLoadingIncidents] = useState(true);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] =
    useState<ActiveIncidentsStatusFilter>("active_incidents");
  const [dateFilter, setDateFilter] = useState<ActiveIncidentsDateFilter>("all_dates");

  const filteredIncidents = useMemo(
    () => filterActiveIncidents(incidents, statusFilter, dateFilter),
    [incidents, statusFilter, dateFilter],
  );

  const filteredIncidentUuids = useMemo(
    () => filteredIncidents.map((incident) => incident.publicUuid),
    [filteredIncidents],
  );

  const { getCardLocation, resetCardLocations } = useActiveIncidentCardLocations(
    isLoadingIncidents ? [] : filteredIncidentUuids,
  );

  const loadIncidents = useCallback(async () => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      router.replace("/auth/login");
      return;
    }

    setIsLoadingIncidents(true);
    setIncidentsError(null);

    try {
      const data = await getOperationsIncidents({
        limit: LIST_LIMIT,
        offset: LIST_OFFSET,
      });

      const nonTerminal = filterNonTerminalOperationsIncidents(
        data.incidents ?? [],
      );

      const mapped = nonTerminal
        .map(mapOperationsIncidentToActiveListItem)
        .filter((item): item is ActiveIncidentListItem => item != null);

      setIncidents(mapped);
      resetCardLocations();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load active incidents", err);
      }
      setIncidentsError(
        err instanceof Error
          ? err.message
          : "Incident data could not be retrieved. Try again.",
      );
      setIncidents([]);
    } finally {
      setIsLoadingIncidents(false);
    }
  }, [router, resetCardLocations]);

  useEffect(() => {
    if (isChecking) return;
    void loadIncidents();
  }, [isChecking, loadIncidents]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const handleNewStandaloneIncident = () => {
    router.push("/dashboard/dispatcher/incidents/create-incident");
  };

  if (isChecking) {
    return <PageLoading label="Loading active incidents" />;
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
              <h2 className="text-xl font-semibold text-slate-900">Active Incidents</h2>
              <p className="mt-0.5 text-sm text-slate-600">
                Monitor ongoing emergency incidents and open command workflows.
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="shrink-0"
              onClick={handleNewStandaloneIncident}
            >
              + New Standalone Incident
            </Button>
          </header>

          <ActiveIncidentsToolbar
            statusFilter={statusFilter}
            dateFilter={dateFilter}
            resultCount={filteredIncidents.length}
            onStatusChange={setStatusFilter}
            onDateChange={setDateFilter}
          />

          <ActiveIncidentsList
            className="min-h-0 flex-1"
            items={filteredIncidents}
            getCardLocation={getCardLocation}
            isLoading={isLoadingIncidents}
            error={incidentsError}
            onRetry={() => void loadIncidents()}
            onNewIncident={handleNewStandaloneIncident}
          />
        </div>
      </DispatcherOpsShell>
    </DashboardLayout>
  );
}
