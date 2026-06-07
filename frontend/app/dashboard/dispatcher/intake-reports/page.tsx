"use client";

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { IntakeQueueList } from "@/components/dispatcher/triage/IntakeQueueList";
import { mapOperationsIntakeList } from "@/components/dispatcher/triage/mapOperationsIntake";
import { TriageReviewRouteWorkspace } from "@/components/dispatcher/triage/TriageReviewRouteWorkspace";
import { TriageQueueToolbar } from "@/components/dispatcher/triage/TriageQueueToolbar";
import type {
  IntakeQueueItem,
  TriageCategoryFilter,
  TriageSortOrder,
  TriageStatusFilter,
} from "@/components/dispatcher/triage/types";
import { PageLoading } from "@/components/ui/StatusState";
import { ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import {
  fetchDispatcherOverview,
  fetchPendingIntakeReports,
  mapApiErrorToTriageMessage,
} from "@/lib/operations-intake-triage";

function resolveQueueSelectionId(
  mapped: IntakeQueueItem[],
  current: string,
  preferredId?: string | null,
): string {
  if (current && mapped.some((item) => item.id === current)) {
    return current;
  }
  if (preferredId && mapped.some((item) => item.id === preferredId)) {
    return preferredId;
  }
  return mapped[0]?.id ?? "";
}

function TriageQueuePageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const reportParam = searchParams.get("report")?.trim() || null;
  const pendingDeepLinkRef = useRef<string | null>(null);
  const prevReportParamRef = useRef<string | null>(null);
  const isChecking = useDispatcherWorkspaceGuard();
  const [queueItems, setQueueItems] = useState<IntakeQueueItem[]>([]);
  const [queueLoading, setQueueLoading] = useState(true);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const [statusFilter, setStatusFilter] = useState<TriageStatusFilter>("all");
  const [categoryFilter, setCategoryFilter] =
    useState<TriageCategoryFilter>("all");
  const [sortOrder, setSortOrder] = useState<TriageSortOrder>("newest");
  const [selectedId, setSelectedId] = useState("");
  const [selectionBlocked, setSelectionBlocked] = useState(false);

  const hasActiveFilters =
    statusFilter !== "all" || categoryFilter !== "all";
  const queueEmpty =
    !queueLoading && !queueError && queueItems.length === 0 && !hasActiveFilters;
  const isFilteredEmpty =
    !queueLoading && !queueError && queueItems.length === 0 && hasActiveFilters;

  const loadOverview = useCallback(async () => {
    try {
      const overview = await fetchDispatcherOverview();
      setPendingCount(overview.counts.intake_reports_pending_classification);
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load dispatcher overview", err);
      }
    }
  }, []);

  const loadQueue = useCallback(
    async (options?: { preserveSelection?: boolean }): Promise<IntakeQueueItem[]> => {
      const accessToken = await ensureAuthSession();
      if (!accessToken) {
        router.push("/auth/login");
        return [];
      }

      const preferredId = pendingDeepLinkRef.current;
      if (preferredId) {
        pendingDeepLinkRef.current = null;
      }

      setQueueLoading(true);
      setQueueError(null);

      try {
        const reports = await fetchPendingIntakeReports({
          statusFilter,
          categoryFilter,
          sortOrder,
        });
        const mapped = mapOperationsIntakeList(reports);
        setQueueItems(mapped);

        if (!options?.preserveSelection) {
          setSelectedId((current) =>
            resolveQueueSelectionId(mapped, current, preferredId),
          );
        }

        return mapped;
      } catch (err) {
        if (process.env.NODE_ENV === "development") {
          console.error("Failed to load triage queue", err);
        }
        setQueueError(mapApiErrorToTriageMessage(err, "queue"));
        setQueueItems([]);
        if (!options?.preserveSelection) {
          setSelectedId("");
        }
        return [];
      } finally {
        setQueueLoading(false);
      }
    },
    [router, statusFilter, categoryFilter, sortOrder],
  );

  const handleSelectIntake = useCallback(
    (id: string) => {
      if (selectionBlocked) return;
      setSelectedId(id);
    },
    [selectionBlocked],
  );

  const handleContinueTriage = useCallback(async () => {
    const priorIndex = queueItems.findIndex((item) => item.id === selectedId);
    const preferredNextId = queueItems[priorIndex + 1]?.id;

    const mapped = await loadQueue({ preserveSelection: true });

    let nextId = "";
    if (preferredNextId && mapped.some((item) => item.id === preferredNextId)) {
      nextId = preferredNextId;
    } else if (priorIndex >= 0 && mapped[priorIndex]?.id) {
      nextId = mapped[priorIndex].id;
    } else {
      nextId = mapped[0]?.id ?? "";
    }

    setSelectedId(nextId);
  }, [loadQueue, queueItems, selectedId]);

  useEffect(() => {
    if (reportParam === prevReportParamRef.current) return;
    prevReportParamRef.current = reportParam;

    if (!reportParam) return;

    pendingDeepLinkRef.current = reportParam;

    if (isChecking || queueLoading) return;

    const match = queueItems.find((item) => item.id === reportParam);
    if (match) {
      setSelectedId(reportParam);
    }
  }, [reportParam, isChecking, queueLoading, queueItems]);

  useEffect(() => {
    if (isChecking) return;
    void loadOverview();
    void loadQueue();
  }, [isChecking, loadOverview, loadQueue]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const pendingLabel =
    pendingCount === 1
      ? "1 Pending Report"
      : `${pendingCount} Pending Reports`;

  if (isChecking) {
    return <PageLoading label="Loading triage queue" />;
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
        <div className="flex min-h-0 flex-1 flex-col gap-3 lg:min-h-0 lg:overflow-hidden">
          <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-hidden lg:min-h-0 lg:grid-cols-[0.89fr_1fr] lg:items-stretch lg:overflow-hidden">
            <div className="flex min-h-0 min-w-0 flex-col gap-3 lg:min-h-0 lg:overflow-hidden">
              <div className="shrink-0 space-y-3">
                <header>
                  <h2 className="text-xl font-semibold text-slate-900">
                    Triage Queue
                  </h2>
                  <p className="mt-0.5 text-sm text-slate-600">
                    Review incoming reports and route them to the appropriate
                    response workflow.
                  </p>
                </header>

                <TriageQueueToolbar
                  statusFilter={statusFilter}
                  categoryFilter={categoryFilter}
                  sortOrder={sortOrder}
                  onStatusChange={setStatusFilter}
                  onCategoryChange={setCategoryFilter}
                  onSortChange={setSortOrder}
                />
              </div>

              <IntakeQueueList
                pendingLabel={pendingLabel}
                className="min-h-0 flex-1 lg:min-h-0"
                items={queueItems}
                selectedId={selectedId || null}
                queueEmpty={queueEmpty}
                isFilteredEmpty={isFilteredEmpty}
                isLoading={queueLoading}
                queueError={queueError}
                onSelect={handleSelectIntake}
                onRetry={() => void loadQueue()}
              />
            </div>

            <div className="flex min-h-0 min-w-0 flex-col lg:overflow-hidden">
              <TriageReviewRouteWorkspace
                className="h-full min-h-0 flex-1"
                reportId={selectedId || null}
                enabled={Boolean(selectedId)}
                queueEmpty={queueEmpty}
                showPanelHeader
                continueAfterSuccess="advance-queue"
                onAfterRouteSuccess={async () => {
                  await Promise.all([
                    loadQueue({ preserveSelection: true }),
                    loadOverview(),
                  ]);
                }}
                onAfterLocationUpdate={async () => {
                  await loadQueue({ preserveSelection: true });
                }}
                onContinueAdvanceQueue={handleContinueTriage}
                onWorkflowStateChange={({ isSuccessMode }) => {
                  setSelectionBlocked(isSuccessMode);
                }}
              />
            </div>
          </div>
        </div>
      </DispatcherOpsShell>
    </DashboardLayout>
  );
}

export default function TriageQueuePage() {
  return (
    <Suspense fallback={<PageLoading label="Loading triage queue" />}>
      <TriageQueuePageContent />
    </Suspense>
  );
}
