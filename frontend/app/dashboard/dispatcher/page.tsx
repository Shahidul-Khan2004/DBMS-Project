"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession } from "@/lib/auth-store";
import type { LoginResponse } from "@/types/auth";
import type { DispatcherOverviewResponse } from "@/types/operations-overview";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

function formatAgeBrief(ageMinutes: number): string {
  const m = Math.max(0, Math.floor(ageMinutes));
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  const d = Math.floor(h / 24);
  return `${d}d`;
}

function formatOccurredAt(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
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
    const accessToken = localStorage.getItem("accessToken");
    if (!accessToken) {
      router.push("/auth/login");
      return;
    }

    setOverviewLoading(true);
    setOverviewError(null);

    try {
      const response = await fetch(`${API_BASE}/operations/dispatcher/overview`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      const data = (await response.json().catch(() => ({}))) as
        | DispatcherOverviewResponse
        | { error?: { message?: string }; message?: string };

      if (!response.ok) {
        let errMsg = "Could not load dispatcher overview.";

        if ("error" in data && data.error?.message) {
          errMsg = data.error.message;
        } else if ("message" in data && typeof data.message === "string") {
          errMsg = data.message;
        }

        setOverviewError(errMsg);
        setOverview(null);
        return;
      }

      setOverview(data as DispatcherOverviewResponse);
    } catch {
      setOverviewError("Unexpected error while loading overview.");
      setOverview(null);
    } finally {
      setOverviewLoading(false);
    }
  }, [router]);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    const accessToken = localStorage.getItem("accessToken");

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
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    );
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

  return (
    <DashboardLayout
      title="NIERS Dispatcher Console"
      subtitle="Read-only overview — intakes, incidents, and service cases"
      onLogout={handleLogout}
    >
      <div className="grid gap-6 md:grid-cols-3">
        <Card className="shadow-md md:col-span-3">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Dispatcher Info
            </h2>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600">
              Name: <span className="font-medium">{user?.full_name}</span>
            </p>
            <p className="mt-2 text-sm text-gray-500">User ID: {user?.id}</p>
            <p className="mt-2 text-sm text-gray-500">{user?.email}</p>
          </CardContent>
        </Card>

        {overviewError && (
          <div className="md:col-span-3 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
            <p>{overviewError}</p>
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
            <h2 className="text-lg font-semibold text-gray-900">
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
            <h2 className="text-lg font-semibold text-gray-900">
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
            <h2 className="text-lg font-semibold text-gray-900">
              Open service cases
            </h2>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-600">
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
              <h2 className="text-lg font-semibold text-gray-900">
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
              <div className="border-t border-gray-100 px-6 py-10 text-center text-sm text-gray-500">
                No pending intakes, active incidents, or open service cases in
                the recent window.
              </div>
            ) : null}

            {overview && overview.recent.length > 0 ? (
              <ul className="divide-y divide-gray-100 border-t border-gray-100">
                {overview.recent.map((row) => (
                  <li
                    key={`${row.kind}-${row.public_uuid}`}
                    className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between sm:gap-x-4 sm:px-6"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="inline-flex rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium uppercase text-gray-700">
                          {row.kind.replace(/_/g, " ")}
                        </span>
                        <span className="text-xs text-gray-500">
                          {formatAgeBrief(row.age_minutes)} ago
                        </span>
                      </div>
                      <p className="mt-1 font-medium text-gray-900 line-clamp-2">
                        {row.summary?.trim() || "(No summary)"}
                      </p>
                      <p className="mt-0.5 text-sm text-gray-600">
                        <span className="font-medium text-gray-700">
                          {row.status}
                        </span>
                        <span className="mx-1.5 text-gray-300">·</span>
                        <span className="text-gray-500">{row.category}</span>
                      </p>
                    </div>
                    <div className="shrink-0 text-xs text-gray-400 sm:text-right">
                      {formatOccurredAt(row.occurred_at)}
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
