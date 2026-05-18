"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import {
  EmptyState,
  PageHeader,
  PageLoading,
} from "@/components/ui/StatusState";
import { apiGet, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import type { LoginResponse } from "@/types/auth";
import type {
  DispatcherOverviewRecentKind,
  DispatcherOverviewResponse,
} from "@/types/operations-overview";

function formatAgeBrief(ageMinutes: number): string {
  const m = Math.max(0, Math.floor(ageMinutes));
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  const d = Math.floor(h / 24);
  return `${d}d`;
}

function getKindStyles(kind: DispatcherOverviewRecentKind) {
  return kind === "incident"
    ? "emergency"
    : kind === "service_case"
      ? "in_progress"
      : "under_review";
}

function getKindLabel(kind: DispatcherOverviewRecentKind) {
  return kind === "intake_report"
    ? "Intake Report"
    : kind === "service_case"
    ? "Service Case"
    : "Incident";
}

function getIntakeCreateIncidentHref(publicUuid: string) {
  const query = new URLSearchParams({
    mode: "intake",
    intakeReportPublicUuid: publicUuid,
  });

  return `/dashboard/dispatcher/incidents/create-incident?${query.toString()}`;
}

function getRecentDetailHref(row: {
  kind: DispatcherOverviewRecentKind;
  public_uuid: string;
}) {
  if (row.kind === "incident") {
    return `/dashboard/dispatcher/incidents/${row.public_uuid}`;
  }
  if (row.kind === "intake_report") {
    return `/dashboard/dispatcher/intake-reports/${row.public_uuid}`;
  }
  return null;
}

function getRecentActivityPreview(overview: DispatcherOverviewResponse | null) {
  return overview?.recent.slice(0, 3) ?? [];
}

export default function DispatcherDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [overview, setOverview] = useState<DispatcherOverviewResponse | null>(
    null,
  );
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewError, setOverviewError] = useState<string | null>(null);

  const loadOverview = useCallback(async () => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      router.push("/auth/login");
      return;
    }

    setOverviewLoading(true);
    setOverviewError(null);

    try {
      const data = await apiGet<DispatcherOverviewResponse>(
        "/operations/dispatcher/overview",
      );
      setOverview(data);
    } catch (err) {
      setOverviewError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading overview.",
      );
      setOverview(null);
    } finally {
      setOverviewLoading(false);
    }
  }, [router]);

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const accessToken = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");

      if (cancelled) return;

      if (!sessionUser || !accessToken) {
        router.push("/auth/login");
        return;
      }

      try {
        const parsedUser = JSON.parse(sessionUser);
        setUser(parsedUser);
      } catch {
        router.push("/auth/login");
        return;
      }

      setIsLoadingSession(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [router]);

  useEffect(() => {
    if (isLoadingSession) return;
    void loadOverview();
  }, [isLoadingSession, loadOverview]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isLoadingSession) {
    return <PageLoading label="Loading dispatcher console" />;
  }

  function renderMetricValue(display: ReactNode) {
    if (overviewLoading && overview === null) {
      return (
        <div
          className="h-9 w-16 animate-pulse rounded bg-gray-200"
          aria-hidden
        />
      );
    }
    return display;
  }

  const counts = overview?.counts;
  const recentActivityPreview = getRecentActivityPreview(overview);

  return (
    <DashboardLayout
      title="NIERS Dispatcher Console"
      subtitle="Read-only overview — intakes, incidents, and service cases"
      onLogout={handleLogout}
    >
      <div className="grid gap-6 md:grid-cols-3">
        <div className="md:col-span-3">
          <PageHeader
            eyebrow="Dispatcher overview"
            title={
              user?.full_name
                ? `Welcome, ${user.full_name}`
                : "Dispatcher console"
            }
            description="Monitor active incidents, intake reports, and service cases from one operations workspace."
            meta={
              <p className="break-words text-sm text-gray-600">
                {user?.email ?? "Signed in dispatcher"}
              </p>
            }
            actions={
              <>
              <Button
                type="button"
                variant="primary"
                onClick={() => router.push("/dashboard/dispatcher/intake-reports")}
              >
                View Intake Reports
              </Button>
              <Button
                type="button"
                variant="primary"
                onClick={() => router.push("/dashboard/dispatcher/service-cases")}
              >
                View Service Cases
              </Button>
              <Button
                type="button"
                variant="primary"
                onClick={() => router.push("/dashboard/dispatcher/incidents")}
              >
                View Incidents
              </Button>
            </>
            }
          />
        </div>

        {overviewError && (
          <div className="md:col-span-3">
            <ErrorAlert message={overviewError} />
            <Button
              type="button"
              variant="secondary"
              className="mt-3"
              onClick={() => void loadOverview()}
            >
              Retry
            </Button>
          </div>
        )}

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-[#002D62]">
              Active incidents
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">
              {renderMetricValue(
                <span aria-live="polite">
                  {counts !== undefined ? counts.incidents_active : "—"}
                </span>,
              )}
            </div>
            <p className="mt-2 text-sm text-gray-600">
              Non-terminal emergency incidents
            </p>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-[#002D62]">
              Pending intakes
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-yellow-600">
              {renderMetricValue(
                <span aria-live="polite">
                  {counts !== undefined
                    ? counts.intake_reports_pending_classification
                    : "—"}
                </span>,
              )}
            </div>
            <p className="mt-2 text-sm text-gray-600">
              Received / under review awaiting classification
            </p>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-[#002D62]">
              Open service cases
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-[#002D62]">
              {renderMetricValue(
                <span aria-live="polite">
                  {counts !== undefined ? counts.service_cases_open : "—"}
                </span>,
              )}
            </div>
            <p className="mt-2 text-sm text-gray-600">
              Non-terminal service cases in queue
            </p>
          </CardContent>
        </Card>

        <Card className="shadow-md md:col-span-3" id="recent-activity">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-semibold text-[#002D62]">
                Recent activity
              </h2>
              {!overviewLoading && (
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => void loadOverview()}
                >
                  Refresh
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-0 sm:p-0">
            {overviewLoading && overview === null && !overviewError ? (
              <div className="border-t border-gray-100 px-6 py-10 text-center text-sm text-gray-500">
                Loading recent items…
              </div>
            ) : null}

            {overview && overview.recent.length === 0 && !overviewLoading ? (
              <div className="p-6">
                <EmptyState
                  title="No recent operations activity"
                  description="Pending intakes, active incidents, and open service cases will appear here as soon as the backend returns them."
                />
              </div>
            ) : null}

            {overview && recentActivityPreview.length > 0 ? (
              <ul className="divide-y divide-gray-100 border-t border-gray-100">
                {recentActivityPreview.map((row) => (
                  <li
                    key={`${row.kind}-${row.public_uuid}`}
                    className="flex flex-col gap-4 border-b border-gray-100 px-4 py-4 sm:flex-row sm:items-start sm:justify-between sm:px-6"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={getKindStyles(row.kind)}>
                          {getKindLabel(row.kind)}
                        </Badge>
                        <span className="text-xs text-gray-500">
                          {formatAgeBrief(row.age_minutes)} ago
                        </span>
                      </div>
                      <p className="mt-2 text-base font-semibold text-gray-900">
                        {row.summary?.trim() || "(No summary)"}
                      </p>
                      <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-gray-600">
                        <span className="font-medium text-gray-700">{row.status}</span>
                        <span className="text-gray-300">·</span>
                        <span>{row.category}</span>
                        <span className="text-gray-300">·</span>
                        <span className="text-gray-700">ID:</span>
                        <span>{row.public_uuid}</span>
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-col items-start gap-2 text-sm text-gray-500 sm:items-end">
                      <p>{formatBangladeshTime(row.occurred_at)}</p>
                      <p className="mt-1">Occurred</p>
                      <div className="flex flex-wrap justify-end gap-2">
                        {getRecentDetailHref(row) ? (
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            onClick={() => {
                              const href = getRecentDetailHref(row);
                              if (href) router.push(href);
                            }}
                          >
                            Open
                          </Button>
                        ) : null}

                        {row.kind === "intake_report" ? (
                          <Button
                            type="button"
                            size="sm"
                            onClick={() =>
                              router.push(getIntakeCreateIncidentHref(row.public_uuid))
                            }
                          >
                            Create Incident
                          </Button>
                        ) : null}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : null}

            {overviewLoading && overview !== null ? (
              <div className="border-t border-gray-100 px-6 py-2 text-center text-xs text-gray-400">
                Refreshing…
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
