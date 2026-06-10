"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import {
  CommandCenterColumnPanel,
  CommandCenterDropZonePlaceholder,
  CommandCenterIncidentCard,
  CommandCenterIntakeCard,
  CommandCenterServiceCaseCard,
} from "@/components/dispatcher/command-center";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { TriageReviewRouteDrawer } from "@/components/dispatcher/triage/TriageReviewRouteDrawer";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { PageLoading } from "@/components/ui/StatusState";
import { apiGet, ensureAuthSession } from "@/lib/api";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { OPS_DASHBOARD_CONTENT_CLASS } from "@/lib/dashboard-viewport";
import { clearAuthSession } from "@/lib/auth-store";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";
import {
  getServiceCaseStatusLabel,
  isServiceCaseOpen,
} from "@/lib/service-case-status";
import { formatRelativeAge } from "@/lib/format-relative-age";
import { sortNewestFirst } from "@/lib/sort";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportsResponse,
} from "@/types/operations-intake";
import type { DispatcherOverviewResponse } from "@/types/operations-overview";
import type {
  OperationsServiceCase,
  OperationsServiceCaseListResponse,
} from "@/types/service-case";

const TERMINAL_INCIDENT_STATUSES = new Set(["resolved", "closed", "cancelled"]);

const INTAKE_STATUS_LABELS: Record<string, string> = {
  received: "Received",
  under_review: "Under Review",
};

const SERVICE_CASE_PRIORITY_RANK: Record<string, number> = {
  urgent: 0,
  high: 1,
  medium: 2,
  low: 3,
};

interface OperationsIncident {
  public_uuid: string;
  incident_code: string;
  title: string;
  description: string | null;
  origin_type: string;
  status_code: string;
  category_code: string;
  severity_code: string;
  outcome_code?: string | null;
  reported_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface IncidentsResponse {
  incidents: OperationsIncident[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

type OverviewCounts = DispatcherOverviewResponse["counts"];

function formatReadableLabel(value: string | null | undefined): string {
  if (!value) return "-";
  return value
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

function formatIntakeStatusLabel(status: string): string {
  return INTAKE_STATUS_LABELS[status] ?? formatReadableLabel(status);
}

function formatCommandCenterIntakeLocation(report: OperationsIntakeReport): string {
  const location = report.location;
  const text =
    location?.address_text?.trim() ||
    location?.place_name?.trim() ||
    report.location_text?.trim();

  if (text) return text;

  if (
    location &&
    (Number.isFinite(location.latitude) || Number.isFinite(location.longitude))
  ) {
    return "Location recorded";
  }

  if (location) return "Location recorded";

  return "Location unavailable";
}

function sortOldestFirst<T>(
  items: T[],
  getTimestampValues: (item: T) => Array<string | null | undefined>,
) {
  return sortNewestFirst(items, getTimestampValues).reverse();
}

function getServiceCasePriorityRank(priorityLevel: string | null | undefined) {
  if (!priorityLevel) return 99;
  return SERVICE_CASE_PRIORITY_RANK[priorityLevel] ?? 99;
}

function dedupeByPublicUuid<T extends { public_uuid: string }>(items: T[]): T[] {
  const seen = new Map<string, T>();
  for (const item of items) {
    if (!seen.has(item.public_uuid)) {
      seen.set(item.public_uuid, item);
    }
  }
  return [...seen.values()];
}

function sortServiceCasesForBoard(cases: OperationsServiceCase[]) {
  const ranks = [0, 1, 2, 3, 99];
  const result: OperationsServiceCase[] = [];

  for (const rank of ranks) {
    const group = cases.filter(
      (serviceCase) => getServiceCasePriorityRank(serviceCase.priority_level) === rank,
    );
    result.push(
      ...sortNewestFirst(group, (serviceCase) => [
        serviceCase.last_updated,
        serviceCase.created_at,
      ]),
    );
  }

  return result;
}

function ColumnBody({
  loading,
  error,
  isEmpty,
  emptyMessage,
  onRetry,
  children,
}: {
  loading: boolean;
  error: string | null;
  isEmpty: boolean;
  emptyMessage: string;
  onRetry: () => void;
  children: ReactNode;
}) {
  if (error) {
    return (
      <div className="space-y-2">
        <ErrorAlert message={error} />
        <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      </div>
    );
  }

  if (loading && isEmpty) {
    return <LoadingSkeleton lines={3} />;
  }

  if (isEmpty) {
    return (
      <p className="py-6 text-center text-xs text-slate-500">{emptyMessage}</p>
    );
  }

  return <>{children}</>;
}

export default function DispatcherDashboard() {
  const router = useRouter();
  const isChecking = useDispatcherWorkspaceGuard();
  const [isRefreshing, setIsRefreshing] = useState(false);

  const [counts, setCounts] = useState<OverviewCounts | null>(null);
  const [countsLoading, setCountsLoading] = useState(false);
  const [countsError, setCountsError] = useState<string | null>(null);

  const [triageItems, setTriageItems] = useState<OperationsIntakeReport[]>([]);
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);

  const [incidentItems, setIncidentItems] = useState<OperationsIncident[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);

  const [caseItems, setCaseItems] = useState<OperationsServiceCase[]>([]);
  const [casesLoading, setCasesLoading] = useState(false);
  const [casesError, setCasesError] = useState<string | null>(null);

  const [reviewDrawerOpen, setReviewDrawerOpen] = useState(false);
  const [reviewReportUuid, setReviewReportUuid] = useState<string | null>(null);

  const redirectToLogin = useCallback(() => {
    router.push("/auth/login");
  }, [router]);

  const loadCounts = useCallback(async () => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setCountsLoading(true);
    setCountsError(null);

    try {
      const data = await apiGet<DispatcherOverviewResponse>(
        "/operations/dispatcher/overview",
      );
      setCounts(data.counts);
    } catch (err) {
      setCountsError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading overview counts.",
      );
      setCounts(null);
    } finally {
      setCountsLoading(false);
    }
  }, [redirectToLogin]);

  const loadTriage = useCallback(async () => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setTriageLoading(true);
    setTriageError(null);

    try {
      const baseParams = {
        limit: "10",
        offset: "0",
        sort: "reported_at_asc",
      };

      const [receivedData, underReviewData] = await Promise.all([
        apiGet<OperationsIntakeReportsResponse>(
          `/operations/intake-reports?${new URLSearchParams({
            ...baseParams,
            intake_status: "received",
          }).toString()}`,
        ),
        apiGet<OperationsIntakeReportsResponse>(
          `/operations/intake-reports?${new URLSearchParams({
            ...baseParams,
            intake_status: "under_review",
          }).toString()}`,
        ),
      ]);

      const merged = dedupeByPublicUuid([
        ...(receivedData.intake_reports ?? []),
        ...(underReviewData.intake_reports ?? []),
      ]);

      setTriageItems(
        sortOldestFirst(merged, (report) => [
          report.reported_at,
          report.created_at,
          report.updated_at,
        ]).slice(0, 5),
      );
    } catch (err) {
      setTriageError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading pending triage.",
      );
      setTriageItems([]);
    } finally {
      setTriageLoading(false);
    }
  }, [redirectToLogin]);

  const loadIncidents = useCallback(async () => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setIncidentsLoading(true);
    setIncidentsError(null);

    try {
      const data = await apiGet<IncidentsResponse>(
        "/operations/incidents?limit=100&offset=0",
      );

      const active = (data.incidents ?? []).filter(
        (incident) => !TERMINAL_INCIDENT_STATUSES.has(incident.status_code),
      );

      setIncidentItems(
        sortNewestFirst(active, (incident) => [
          incident.reported_at,
          incident.updated_at,
          incident.created_at,
        ]).slice(0, 5),
      );
    } catch (err) {
      setIncidentsError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading active incidents.",
      );
      setIncidentItems([]);
    } finally {
      setIncidentsLoading(false);
    }
  }, [redirectToLogin]);

  const loadServiceCases = useCallback(async () => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setCasesLoading(true);
    setCasesError(null);

    try {
      const baseParams = { limit: "10", offset: "0" };
      const statuses = ["submitted", "under_review", "awaiting_user_response"] as const;

      const responses = await Promise.all(
        statuses.map((status) =>
          apiGet<OperationsServiceCaseListResponse>(
            `/operations/service-cases?${new URLSearchParams({
              ...baseParams,
              status,
            }).toString()}`,
          ),
        ),
      );

      const merged = dedupeByPublicUuid(
        responses.flatMap((response) => response.service_cases ?? []),
      ).filter((serviceCase) => isServiceCaseOpen(serviceCase.status_code));

      setCaseItems(sortServiceCasesForBoard(merged).slice(0, 5));
    } catch (err) {
      setCasesError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading service cases.",
      );
      setCaseItems([]);
    } finally {
      setCasesLoading(false);
    }
  }, [redirectToLogin]);

  const loadCommandCenter = useCallback(async () => {
    setIsRefreshing(true);
    await Promise.all([
      loadCounts(),
      loadTriage(),
      loadIncidents(),
      loadServiceCases(),
    ]);
    setIsRefreshing(false);
  }, [loadCounts, loadTriage, loadIncidents, loadServiceCases]);

  useEffect(() => {
    if (isChecking) return;
    void loadCommandCenter();
  }, [isChecking, loadCommandCenter]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const openReviewDrawer = (publicUuid: string) => {
    setReviewReportUuid(publicUuid);
    setReviewDrawerOpen(true);
  };

  const handleReviewDrawerOpenChange = (open: boolean) => {
    setReviewDrawerOpen(open);
    if (!open) {
      setReviewReportUuid(null);
    }
  };

  const openIncidentDetail = (publicUuid: string) => {
    router.push(`/dashboard/dispatcher/incidents/${publicUuid}`);
  };

  const openServiceCaseDetail = (publicUuid: string) => {
    router.push(`/dashboard/dispatcher/service-cases/${publicUuid}`);
  };

  if (isChecking) {
    return <PageLoading label="Loading command center" />;
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
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col overflow-hidden lg:min-h-0">
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden lg:overflow-hidden">
          <header className="mb-4 flex shrink-0 flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold text-slate-900">Command Center</h2>
              <p className="mt-0.5 text-sm text-slate-600">
                Route incoming reports and monitor active response operations.
              </p>
              {countsError ? (
                <p className="mt-1 text-xs text-red-600" role="alert">
                  Counts unavailable: {countsError}
                </p>
              ) : null}
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={isRefreshing}
                onClick={() => void loadCommandCenter()}
              >
                {isRefreshing ? "Refreshing…" : "Refresh"}
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  router.push("/dashboard/dispatcher/incidents/create-incident")
                }
              >
                + New Standalone Incident
              </Button>
            </div>
          </header>

          <div className="grid min-h-0 flex-1 gap-4 lg:min-h-0 lg:grid-cols-[minmax(320px,32fr)_minmax(420px,36fr)_minmax(320px,32fr)] lg:overflow-hidden">
            <CommandCenterColumnPanel
              column="triage"
              title="Pending Triage"
              count={counts?.intake_reports_pending_classification ?? null}
              countLoading={countsLoading}
              subtitle="Incoming reports awaiting decision"
            >
              <ColumnBody
                loading={triageLoading}
                error={triageError}
                isEmpty={triageItems.length === 0}
                emptyMessage="No reports awaiting triage."
                onRetry={() => void loadTriage()}
              >
                {triageItems.map((report) => (
                  <CommandCenterIntakeCard
                    key={report.public_uuid}
                    report={report}
                    categoryLabel={formatReadableLabel(report.category_code)}
                    locationLabel={formatCommandCenterIntakeLocation(report)}
                    statusLabel={formatIntakeStatusLabel(report.intake_status)}
                    ageLabel={formatRelativeAge(report.reported_at)}
                    onProcessReport={openReviewDrawer}
                    onViewDetails={openReviewDrawer}
                  />
                ))}
              </ColumnBody>
            </CommandCenterColumnPanel>

            <CommandCenterColumnPanel
              column="incidents"
              title="Active Incidents"
              count={counts?.incidents_active ?? null}
              countLoading={countsLoading}
              subtitle="Emergency response operations"
              pinned={
                <CommandCenterDropZonePlaceholder>
                  Drop an intake here to create a new emergency incident
                </CommandCenterDropZonePlaceholder>
              }
            >
              <ColumnBody
                loading={incidentsLoading}
                error={incidentsError}
                isEmpty={incidentItems.length === 0}
                emptyMessage="No active incidents."
                onRetry={() => void loadIncidents()}
              >
                {incidentItems.map((incident) => (
                  <CommandCenterIncidentCard
                    key={incident.public_uuid}
                    incident={incident}
                    categoryLabel={formatReadableLabel(incident.category_code)}
                    ageLabel={formatRelativeAge(incident.reported_at)}
                    onOpenDetail={openIncidentDetail}
                  />
                ))}
              </ColumnBody>
            </CommandCenterColumnPanel>

            <CommandCenterColumnPanel
              column="service_cases"
              title="Service Cases"
              count={counts?.service_cases_open ?? null}
              countLoading={countsLoading}
              subtitle="Non-emergency follow-up work"
              pinned={
                <CommandCenterDropZonePlaceholder>
                  Drop an intake here to create a service case
                </CommandCenterDropZonePlaceholder>
              }
            >
              <ColumnBody
                loading={casesLoading}
                error={casesError}
                isEmpty={caseItems.length === 0}
                emptyMessage="No open service cases."
                onRetry={() => void loadServiceCases()}
              >
                {caseItems.map((serviceCase) => (
                  <CommandCenterServiceCaseCard
                    key={serviceCase.public_uuid}
                    serviceCase={serviceCase}
                    categoryLabel={formatReadableLabel(serviceCase.category_code)}
                    statusLabel={getServiceCaseStatusLabel(serviceCase.status_code)}
                    updatedLabel={formatRelativeAge(serviceCase.last_updated)}
                    onOpenCase={openServiceCaseDetail}
                  />
                ))}
              </ColumnBody>
            </CommandCenterColumnPanel>
          </div>
        </div>
      </DispatcherOpsShell>

      <TriageReviewRouteDrawer
        open={reviewDrawerOpen}
        reportPublicUuid={reviewReportUuid}
        onOpenChange={handleReviewDrawerOpenChange}
        onRouteSuccess={() => void loadCommandCenter()}
      />
    </DashboardLayout>
  );
}
