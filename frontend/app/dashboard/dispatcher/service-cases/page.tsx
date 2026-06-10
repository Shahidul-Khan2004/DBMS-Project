"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { ServiceCaseQueueList } from "@/components/dispatcher/service-cases/ServiceCaseQueueList";
import { ServiceCasesToolbar } from "@/components/dispatcher/service-cases/ServiceCasesToolbar";
import {
  OPEN_STATUS_FILTER,
  SERVICE_CASE_LIST_FETCH_LIMIT,
  type ServiceCaseSortOrder,
} from "@/components/dispatcher/service-cases/toolbarConfig";
import { Button } from "@/components/ui/Button";
import { PageLoading } from "@/components/ui/StatusState";
import { ensureAuthSession } from "@/lib/api";
import { OPS_DASHBOARD_CONTENT_CLASS } from "@/lib/dashboard-viewport";
import { clearAuthSession } from "@/lib/auth-store";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { isServiceCaseFinal, isServiceCaseOpen } from "@/lib/service-case-status";
import { listOperationsServiceCases } from "@/lib/service-case-api";
import { sortNewestFirst, sortOldestFirst } from "@/lib/sort";
import { sortServiceCasesByPriorityThenUpdated } from "@/lib/sort-service-cases";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";
import type {
  OperationsServiceCase,
} from "@/types/service-case";

function getServiceCaseTimestampValues(serviceCase: OperationsServiceCase) {
  return [serviceCase.last_updated, serviceCase.created_at];
}

function sortVisibleServiceCases(
  cases: OperationsServiceCase[],
  sortOrder: ServiceCaseSortOrder,
): OperationsServiceCase[] {
  switch (sortOrder) {
    case "priority_first":
      return sortServiceCasesByPriorityThenUpdated(cases);
    case "recently_updated":
      return sortNewestFirst(cases, getServiceCaseTimestampValues);
    case "oldest_updated":
      return sortOldestFirst(cases, getServiceCaseTimestampValues);
  }
}

export default function DispatcherServiceCasesPage() {
  const router = useRouter();
  const isChecking = useDispatcherWorkspaceGuard("serviceCases");
  const [serviceCases, setServiceCases] = useState<OperationsServiceCase[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState({
    limit: SERVICE_CASE_LIST_FETCH_LIMIT,
    offset: 0,
    total: 0,
  });
  const [filters, setFilters] = useState({
    status: OPEN_STATUS_FILTER,
    categoryCode: "",
  });
  const [priorityFilter, setPriorityFilter] = useState("");
  const [sortOrder, setSortOrder] = useState<ServiceCaseSortOrder>("priority_first");

  const loadServiceCases = useCallback(
    async (offset = 0) => {
      const accessToken = await ensureAuthSession();

      if (!accessToken) {
        router.push("/auth/login");
        return;
      }

      setIsLoading(true);
      setError(null);

      try {
        const data = await listOperationsServiceCases({
          limit: SERVICE_CASE_LIST_FETCH_LIMIT,
          offset,
          ...(filters.status && filters.status !== OPEN_STATUS_FILTER
            ? { status: filters.status }
            : {}),
          ...(filters.categoryCode ? { categoryCode: filters.categoryCode } : {}),
        });

        setServiceCases(data.service_cases ?? []);
        setPagination(data.pagination);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unexpected error while loading service cases.",
        );
        setServiceCases([]);
      } finally {
        setIsLoading(false);
      }
    },
    [filters, router],
  );

  useEffect(() => {
    if (isChecking) return;
    void loadServiceCases();
  }, [isChecking, loadServiceCases]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  // Priority filter and sort apply to the current API page only; pagination uses server updated_at DESC.
  const visibleServiceCases = useMemo(() => {
    let cases = serviceCases.filter(
      (serviceCase) => !isServiceCaseFinal(serviceCase.status_code),
    );

    if (filters.status === OPEN_STATUS_FILTER) {
      cases = cases.filter((serviceCase) =>
        isServiceCaseOpen(serviceCase.status_code),
      );
    }

    if (priorityFilter) {
      cases = cases.filter(
        (serviceCase) => serviceCase.priority_level === priorityFilter,
      );
    }

    return sortVisibleServiceCases(cases, sortOrder);
  }, [filters.status, priorityFilter, serviceCases, sortOrder]);

  const queueCountLabel = useMemo(() => {
    const count = visibleServiceCases.length;
    return count === 1 ? "1 case" : `${count} cases`;
  }, [visibleServiceCases.length]);

  if (isChecking) {
    return <PageLoading label="Loading service case queue" />;
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
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0">
        <div className="flex min-h-0 flex-1 flex-col gap-4 lg:overflow-hidden">
          <header className="flex shrink-0 flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold text-slate-900">Service Cases</h2>
              <p className="mt-0.5 text-sm text-slate-600">
                Track non-emergency cases requiring follow-up, communication, or resolution.
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="shrink-0"
              onClick={() => void loadServiceCases(pagination.offset)}
              disabled={isLoading}
            >
              {isLoading ? "Refreshing…" : "Refresh"}
            </Button>
          </header>

          <ServiceCasesToolbar
            filters={filters}
            priorityFilter={priorityFilter}
            sortOrder={sortOrder}
            isLoading={isLoading}
            onFiltersChange={(patch) =>
              setFilters((current) => ({ ...current, ...patch }))
            }
            onPriorityFilterChange={setPriorityFilter}
            onSortOrderChange={setSortOrder}
            onApply={() => void loadServiceCases(0)}
          />

          <ServiceCaseQueueList
            className="min-h-0 flex-1"
            items={visibleServiceCases}
            countLabel={queueCountLabel}
            isLoading={isLoading}
            error={error}
            pagination={pagination}
            onRetry={() => void loadServiceCases(pagination.offset)}
            onPreviousPage={() =>
              void loadServiceCases(
                Math.max(0, pagination.offset - pagination.limit),
              )
            }
            onNextPage={() =>
              void loadServiceCases(pagination.offset + pagination.limit)
            }
          />
        </div>
      </DispatcherOpsShell>
    </DashboardLayout>
  );
}
