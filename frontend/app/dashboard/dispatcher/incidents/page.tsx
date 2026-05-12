"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, PageHeader, PageLoading } from "@/components/ui/StatusState";
import { apiGet, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";

interface Incident {
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
  incidents: Incident[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

const fieldClassName =
  "h-10.5 rounded-2xl border border-[#002D62]/20 bg-white px-3 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";

const STATUS_OPTIONS = [
  "reported",
  "classified",
  "in_progress",
  "resolved",
  "closed",
  "cancelled",
];

function truncateText(value: string | null | undefined, maxLength = 140) {
  const text = value?.trim();
  if (!text) return "No description provided.";
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
}

function toIsoDateTime(value: string) {
  return value ? new Date(value).toISOString() : undefined;
}

function normalizeOffset(value: number) {
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}

export default function IncidentsPage() {
  const router = useRouter();
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState({
    limit: 50,
    offset: 0,
    total: 0,
  });
  const [filters, setFilters] = useState({
    status_code: "",
    reported_after: "",
    reported_before: "",
    limit: 50,
  });

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  const loadIncidents = useCallback(
    async (offset = 0) => {
      const accessToken = await ensureAuthSession();
      if (!accessToken) {
        redirectToLogin();
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const data = await apiGet<IncidentsResponse>(
          `/operations/incidents?${new URLSearchParams({
            limit: String(filters.limit),
            offset: String(normalizeOffset(offset)),
            ...(filters.status_code ? { status_code: filters.status_code } : {}),
            ...(filters.reported_after
              ? { reported_after: toIsoDateTime(filters.reported_after) ?? "" }
              : {}),
            ...(filters.reported_before
              ? { reported_before: toIsoDateTime(filters.reported_before) ?? "" }
              : {}),
          }).toString()}`,
        );

        setIncidents(data.incidents);
        setPagination(data.pagination);
        setFilters((current) => ({
          ...current,
          limit: data.pagination.limit,
        }));
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unexpected error while loading incidents.",
        );
        setIncidents([]);
      } finally {
        setLoading(false);
      }
    },
    [filters, redirectToLogin],
  );

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const accessToken = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");

      if (cancelled) return;

      if (!sessionUser || !accessToken) {
        redirectToLogin();
        return;
      }

      setIsLoadingSession(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [redirectToLogin]);

  useEffect(() => {
    if (isLoadingSession) return;
    void loadIncidents(0);
    // Initial load only; filter changes are applied explicitly by the form button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoadingSession]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isLoadingSession) {
    return <PageLoading label="Loading incidents" />;
  }

  const pageCount = Math.ceil(pagination.total / pagination.limit);
  const currentPage = Math.floor(pagination.offset / pagination.limit) + 1;

  return (
    <DashboardLayout
      title="Emergency Incidents"
      subtitle="Operations management for emergency incidents"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <PageHeader
          eyebrow="Emergency operations"
          title="Emergency Incidents"
          description="Filter, review, and create emergency incidents backed by the operations API."
          meta={
            <p className="text-sm text-gray-600">
              Total: {pagination.total} | Showing: {incidents.length}
            </p>
          }
          actions={
            <>
              <Button
                type="button"
                variant="secondary"
                onClick={() => router.push("/dashboard/dispatcher")}
              >
                Back to Dashboard
              </Button>
              <Button
                type="button"
                onClick={() =>
                  router.push("/dashboard/dispatcher/incidents/create-incident")
                }
              >
                Create Incident
              </Button>
            </>
          }
        />

        {error && <ErrorAlert message={error} />}

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-[#002D62]">Filters</h2>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 md:grid-cols-5">
              <label htmlFor="filter-incident-status" className="sr-only">
                Status
              </label>
              <select
                id="filter-incident-status"
                value={filters.status_code}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    status_code: event.target.value,
                  }))
                }
                className={fieldClassName}
              >
                <option value="">All statuses</option>
                {STATUS_OPTIONS.map((status) => (
                  <option key={status} value={status}>
                    {formatBadgeLabel(status)}
                  </option>
                ))}
              </select>

              <label htmlFor="filter-reported-after" className="sr-only">
                Reported after
              </label>
              <input
                id="filter-reported-after"
                type="datetime-local"
                value={filters.reported_after}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    reported_after: event.target.value,
                  }))
                }
                className={fieldClassName}
                aria-label="Reported after"
              />

              <label htmlFor="filter-reported-before" className="sr-only">
                Reported before
              </label>
              <input
                id="filter-reported-before"
                type="datetime-local"
                value={filters.reported_before}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    reported_before: event.target.value,
                  }))
                }
                className={fieldClassName}
                aria-label="Reported before"
              />

              <label htmlFor="filter-limit" className="sr-only">
                Results per page
              </label>
              <select
                id="filter-limit"
                value={filters.limit}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    limit: Number(event.target.value),
                  }))
                }
                className={fieldClassName}
                aria-label="Results per page"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>

              <Button
                type="button"
                onClick={() => void loadIncidents(0)}
                disabled={loading}
              >
                Apply Filters
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-[#002D62]">
              Incidents List
            </h2>
          </CardHeader>
          <CardContent className="p-0">
            {loading && incidents.length === 0 ? (
              <div className="p-6">
                <LoadingSkeleton lines={8} />
              </div>
            ) : incidents.length === 0 ? (
              <div className="p-6">
                <EmptyState
                  title="No incidents found"
                  description="Try a different status or reported time window, then apply filters again."
                />
              </div>
            ) : (
              <ul className="divide-y divide-[#002D62]/10">
                {incidents.map((incident) => (
                  <li key={incident.public_uuid} className="px-4 py-5 sm:px-6">
                    <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded-full bg-white px-2.5 py-1 text-xs font-semibold text-[#002D62]">
                            {incident.incident_code}
                          </span>
                          <Badge tone={incident.status_code}>
                            {formatBadgeLabel(incident.status_code)}
                          </Badge>
                          <Badge tone={incident.severity_code}>
                            {formatBadgeLabel(incident.severity_code)}
                          </Badge>
                          <span className="rounded-full bg-white px-2.5 py-1 text-xs font-medium text-slate-700">
                            {formatBadgeLabel(incident.category_code)}
                          </span>
                          <span className="rounded-full bg-white px-2.5 py-1 text-xs font-medium text-slate-700">
                            {formatBadgeLabel(incident.origin_type)}
                          </span>
                        </div>

                        <h3 className="mt-3 text-lg font-semibold text-gray-900">
                          {incident.title}
                        </h3>
                        <p className="mt-1 text-sm leading-6 text-gray-600">
                          {truncateText(incident.description)}
                        </p>

                        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-6">
                          <div>
                            <dt className="font-medium text-gray-600">
                              Outcome Code
                            </dt>
                            <dd className="mt-1 text-gray-900">
                              {incident.outcome_code
                                ? formatBadgeLabel(incident.outcome_code)
                                : "Detail only"}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-600">
                              Reported
                            </dt>
                            <dd className="mt-1 text-gray-900">
                              {formatBangladeshTime(incident.reported_at)}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-600">
                              Resolved
                            </dt>
                            <dd className="mt-1 text-gray-900">
                              {formatBangladeshTime(incident.resolved_at)}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-600">
                              Closed
                            </dt>
                            <dd className="mt-1 text-gray-900">
                              {formatBangladeshTime(incident.closed_at)}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-600">
                              Created
                            </dt>
                            <dd className="mt-1 text-gray-900">
                              {formatBangladeshTime(incident.created_at)}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-600">
                              Updated
                            </dt>
                            <dd className="mt-1 text-gray-900">
                              {formatBangladeshTime(incident.updated_at)}
                            </dd>
                          </div>
                        </dl>
                      </div>

                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() =>
                          router.push(
                            `/dashboard/dispatcher/incidents/${incident.public_uuid}`,
                          )
                        }
                      >
                        Open Detail
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {pagination.total > pagination.limit && (
          <div className="flex items-center justify-between">
            <Button
              type="button"
              variant="secondary"
              disabled={pagination.offset === 0 || loading}
              onClick={() =>
                void loadIncidents(
                  Math.max(0, pagination.offset - pagination.limit),
                )
              }
            >
              Previous
            </Button>
            <span className="text-sm text-gray-600">
              Page {currentPage} of {pageCount}
            </span>
            <Button
              type="button"
              variant="secondary"
              disabled={
                pagination.offset + pagination.limit >= pagination.total ||
                loading
              }
              onClick={() =>
                void loadIncidents(pagination.offset + pagination.limit)
              }
            >
              Next
            </Button>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
