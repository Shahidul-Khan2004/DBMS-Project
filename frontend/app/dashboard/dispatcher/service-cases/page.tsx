"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageHeader, PageLoading } from "@/components/ui/StatusState";
import { apiGet, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  OperationsServiceCase,
  OperationsServiceCaseListResponse,
} from "@/types/service-case";

const fieldClassName =
  "h-10.5 rounded-2xl border border-[#002D62]/20 bg-white px-3 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";

export default function DispatcherServiceCasesPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["dispatcher", "system_admin"]);
  const [serviceCases, setServiceCases] = useState<OperationsServiceCase[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState({ limit: 50, offset: 0, total: 0 });
  const [filters, setFilters] = useState({ status: "", categoryCode: "", limit: 50 });

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
        const query = new URLSearchParams({
          limit: String(filters.limit),
          offset: String(offset),
          ...(filters.status ? { status: filters.status } : {}),
          ...(filters.categoryCode ? { categoryCode: filters.categoryCode } : {}),
        });

        const data = await apiGet<OperationsServiceCaseListResponse>(
          `/operations/service-cases?${query.toString()}`,
        );

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

  if (isChecking) {
    return <PageLoading label="Loading service case queue" />;
  }

  return (
    <DashboardLayout
      title="Service Cases"
      subtitle="Operations queue for active service cases"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <PageHeader
          eyebrow="Operations queue"
          title="Service Cases"
          description="Review and manage active service cases assigned to operations."
          meta={
            <p className="text-sm text-gray-600">
              Total: {pagination.total} | Showing: {serviceCases.length}
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
                onClick={() => void loadServiceCases()}
                disabled={isLoading}
              >
                {isLoading ? "Loading..." : "Refresh"}
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
            <div className="grid gap-3 md:grid-cols-4">
              <label htmlFor="filter-status" className="sr-only">
                Status
              </label>
              <select
                id="filter-status"
                value={filters.status}
                onChange={(e) =>
                  setFilters((current) => ({ ...current, status: e.target.value }))
                }
                className={fieldClassName}
              >
                <option value="">All statuses</option>
                <option value="submitted">Submitted</option>
                <option value="under_review">Under review</option>
                <option value="awaiting_user_response">Awaiting user response</option>
                <option value="escalated_to_emergency">Escalated to emergency</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
                <option value="cancelled">Cancelled</option>
              </select>

              <label htmlFor="filter-category" className="sr-only">
                Category
              </label>
              <select
                id="filter-category"
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
                onClick={() => void loadServiceCases(0)}
                disabled={isLoading}
              >
                Apply Filters
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-[#002D62]">Service Case Queue</h2>
          </CardHeader>
          <CardContent className="p-0">
            {isLoading && serviceCases.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-gray-500">
                Loading service cases...
              </div>
            ) : serviceCases.length === 0 ? (
              <div className="p-6">
                <EmptyState
                  title="No service cases found"
                  description="Try adjusting filters or refresh when new cases are available."
                />
              </div>
            ) : (
              <ul className="divide-y divide-gray-100">
                {serviceCases.map((serviceCase) => (
                  <li
                    key={serviceCase.public_uuid}
                    className="space-y-4 border-b border-gray-100 px-4 py-5 sm:px-6"
                  >
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="inline-flex rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-slate-700">
                            {serviceCase.case_code}
                          </span>
                          <Badge tone={serviceCase.status_code}>
                            {formatBadgeLabel(serviceCase.status_code)}
                          </Badge>
                          <Badge tone={serviceCase.priority_level}>
                            {formatBadgeLabel(serviceCase.priority_level)}
                          </Badge>
                          <span className="inline-flex rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                            {formatBadgeLabel(serviceCase.category_code)}
                          </span>
                        </div>
                        <p className="mt-3 text-lg font-semibold text-slate-900">
                          {serviceCase.title}
                        </p>
                        <div className="mt-2 flex flex-wrap gap-2 text-sm text-slate-600">
                          <span>Updated: {formatBangladeshTime(serviceCase.last_updated)}</span>
                          <span className="text-slate-300">|</span>
                          <span>Intake: {serviceCase.intake_report_code ?? "-"}</span>
                          <span className="text-slate-300">|</span>
                          <span>
                            Assigned: {serviceCase.assigned_to_user_public_uuid || "Unassigned"}
                          </span>
                        </div>
                      </div>
                      <div className="flex shrink-0 flex-wrap gap-2">
                        <Button
                          type="button"
                          size="sm"
                          onClick={() =>
                            router.push(
                              `/dashboard/dispatcher/service-cases/${serviceCase.public_uuid}`,
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
              disabled={pagination.offset === 0 || isLoading}
              onClick={() =>
                void loadServiceCases(
                  Math.max(0, pagination.offset - pagination.limit),
                )
              }
            >
              Previous
            </Button>
            <span className="text-sm text-gray-600">
              Page {Math.floor(pagination.offset / pagination.limit) + 1} of {Math.ceil(pagination.total / pagination.limit)}
            </span>
            <Button
              type="button"
              variant="secondary"
              disabled={pagination.offset + pagination.limit >= pagination.total || isLoading}
              onClick={() => void loadServiceCases(pagination.offset + pagination.limit)}
            >
              Next
            </Button>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
