"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageHeader, PageLoading } from "@/components/ui/StatusState";
import { apiGet, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportsResponse,
} from "@/types/operations-intake";

function getCreateIncidentHref(reportPublicUuid: string) {
  const query = new URLSearchParams({
    mode: "intake",
    intakeReportPublicUuid: reportPublicUuid,
  });

  return `/dashboard/dispatcher/incidents/create-incident?${query.toString()}`;
}

const fieldClassName =
  "h-10.5 rounded-2xl border border-[#002D62]/20 bg-white px-3 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";

export default function IntakeReportsPage() {
  const router = useRouter();
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [reports, setReports] = useState<OperationsIntakeReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState({
    limit: 50,
    offset: 0,
    total: 0,
  });
  const [filters, setFilters] = useState({
    intake_status: "",
    urgency_type: "",
    categoryCode: "",
    sort: "reported_at_desc",
    limit: 50,
  });

  const loadReports = useCallback(
    async (offset = 0) => {
      const accessToken = await ensureAuthSession();

      if (!accessToken) {
        router.push("/auth/login");
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const data = await apiGet<OperationsIntakeReportsResponse>(
          `/operations/intake-reports?${new URLSearchParams({
            limit: String(filters.limit),
            offset: String(offset),
            ...(filters.intake_status
              ? { intake_status: filters.intake_status }
              : {}),
            ...(filters.urgency_type ? { urgency_type: filters.urgency_type } : {}),
            ...(filters.categoryCode ? { categoryCode: filters.categoryCode } : {}),
            sort: filters.sort,
          }).toString()}`,
        );

        setReports(data.intake_reports);
        setPagination(data.pagination);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unexpected error while loading reports.",
        );
        setReports([]);
      } finally {
        setLoading(false);
      }
    },
    [filters, router]
  );

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
        JSON.parse(sessionUser);
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
    void loadReports();
  }, [isLoadingSession, loadReports]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isLoadingSession) {
    return <PageLoading label="Loading intake queue" />;
  }

  return (
    <DashboardLayout
      title="Intake Reports"
      subtitle="Operations queue for intake reports pending classification"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <PageHeader
          eyebrow="Operations queue"
          title="Intake Reports"
          description="Review citizen and 999 intake reports pending classification or incident linking."
          meta={
            <p className="text-sm text-gray-600">
              Total: {pagination.total} | Showing: {reports.length}
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
              variant="secondary"
              onClick={() => void loadReports()}
              disabled={loading}
            >
              {loading ? "Loading..." : "Refresh"}
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
              <label htmlFor="filter-intake-status" className="sr-only">
                Intake status
              </label>
              <select
                id="filter-intake-status"
                value={filters.intake_status}
                onChange={(e) =>
                  setFilters((current) => ({
                    ...current,
                    intake_status: e.target.value,
                  }))
                }
                className={fieldClassName}
              >
                <option value="">All statuses</option>
                <option value="received">Received</option>
                <option value="under_review">Under review</option>
                <option value="linked_to_case">Linked to case</option>
                <option value="linked_to_incident">Linked to incident</option>
              </select>
              <label htmlFor="filter-urgency-type" className="sr-only">
                Urgency type
              </label>
              <select
                id="filter-urgency-type"
                value={filters.urgency_type}
                onChange={(e) =>
                  setFilters((current) => ({
                    ...current,
                    urgency_type: e.target.value,
                  }))
                }
                className={fieldClassName}
              >
                <option value="">All urgency</option>
                <option value="unknown">Unknown</option>
                <option value="non_emergency">Non-emergency</option>
                <option value="emergency">Emergency</option>
              </select>
              <label htmlFor="filter-category-code" className="sr-only">
                Category code
              </label>
              <select
                id="filter-category-code"
                value={filters.categoryCode}
                onChange={(e) =>
                  setFilters((current) => ({
                    ...current,
                    categoryCode: e.target.value,
                  }))
                }
                className={fieldClassName}
              >
                <option value="">All categories</option>
                <option value="medical">Medical</option>
                <option value="crime_public_safety">Crime / Public Safety</option>
                <option value="fire">Fire</option>
                <option value="natural_disaster">Natural Disaster</option>
                <option value="infrastructure_emergency">Infrastructure</option>
                <option value="relief_request">Relief Request</option>
                <option value="blood_request">Blood Request</option>
              </select>
              <label htmlFor="filter-sort" className="sr-only">
                Sort order
              </label>
              <select
                id="filter-sort"
                value={filters.sort}
                onChange={(e) =>
                  setFilters((current) => ({ ...current, sort: e.target.value }))
                }
                className={fieldClassName}
              >
                <option value="reported_at_desc">Newest first</option>
                <option value="reported_at_asc">Oldest first</option>
              </select>
              <label htmlFor="filter-limit" className="sr-only">
                Results per page
              </label>
              <select
                id="filter-limit"
                value={filters.limit}
                onChange={(e) =>
                  setFilters((current) => ({
                    ...current,
                    limit: Number(e.target.value),
                  }))
                }
                className={fieldClassName}
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
              <Button
                type="button"
                onClick={() => void loadReports(0)}
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
              Reports Queue
            </h2>
          </CardHeader>

          <CardContent className="p-0">
            {loading && reports.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-gray-500">
                Loading reports...
              </div>
            ) : reports.length === 0 ? (
              <div className="p-6">
                <EmptyState
                  title="No intake reports found"
                  description="Try adjusting filters, or refresh when new backend intake reports are available."
                />
              </div>
            ) : (
              <ul className="divide-y divide-gray-100">
                {reports.map((report) => (
                  <li
                    key={report.public_uuid}
                    className="space-y-4 border-b border-gray-100 px-4 py-5 sm:px-6"
                  >
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="inline-flex rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-slate-700">
                            {report.report_code}
                          </span>
                          <Badge tone={report.intake_status}>
                            {formatBadgeLabel(report.intake_status)}
                          </Badge>
                          <Badge tone={report.urgency_type}>
                            {formatBadgeLabel(report.urgency_type)}
                          </Badge>
                          <span className="inline-flex rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                            {report.category_code}
                          </span>
                        </div>

                        <p className="mt-3 text-lg font-semibold text-slate-900">
                          {report.summary}
                        </p>

                        <div className="mt-2 flex flex-wrap gap-2 text-sm text-slate-600">
                          <span>Reported: {formatBangladeshTime(report.reported_at)}</span>
                          <span className="text-slate-300">|</span>
                          <span>Created: {formatBangladeshTime(report.created_at)}</span>
                          <span className="text-slate-300">|</span>
                          <span>Updated: {formatBangladeshTime(report.updated_at)}</span>
                          <span className="text-slate-300">|</span>
                          <span>Service case: {report.has_service_case ? "Yes" : "No"}</span>
                          <span className="text-slate-300">|</span>
                          <span>Incident: {report.has_incident ? "Yes" : "No"}</span>
                        </div>
                      </div>

                      <div className="flex shrink-0 flex-wrap gap-2">
                        {!report.has_incident ? (
                          <Button
                            type="button"
                            size="sm"
                            onClick={() =>
                              router.push(getCreateIncidentHref(report.public_uuid))
                            }
                          >
                            Create Incident
                          </Button>
                        ) : null}

                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={() =>
                            router.push(
                              `/dashboard/dispatcher/intake-reports/${report.public_uuid}`
                            )
                          }
                        >
                          View Details
                        </Button>
                      </div>
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
                void loadReports(
                  Math.max(0, pagination.offset - pagination.limit)
                )
              }
            >
              Previous
            </Button>

            <span className="text-sm text-gray-600">
              Page {Math.floor(pagination.offset / pagination.limit) + 1} of{" "}
              {Math.ceil(pagination.total / pagination.limit)}
            </span>

            <Button
              type="button"
              variant="secondary"
              disabled={
                pagination.offset + pagination.limit >= pagination.total ||
                loading
              }
              onClick={() =>
                void loadReports(pagination.offset + pagination.limit)
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
