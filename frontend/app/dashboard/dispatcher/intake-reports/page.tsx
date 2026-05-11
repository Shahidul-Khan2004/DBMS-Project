"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession } from "@/lib/auth-store";
import type { LoginResponse } from "@/types/auth";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportsResponse,
} from "@/types/operations-intake";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

export default function IntakeReportsPage() {
  const router = useRouter();
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
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
  });

  const loadReports = useCallback(
    async (offset = 0) => {
      const accessToken = localStorage.getItem("accessToken");

      if (!accessToken) {
        router.push("/auth/login");
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const response = await fetch(
          `${API_BASE}/operations/intake-reports?${new URLSearchParams({
            limit: "50",
            offset: String(offset),
            ...(filters.intake_status
              ? { intake_status: filters.intake_status }
              : {}),
            ...(filters.urgency_type ? { urgency_type: filters.urgency_type } : {}),
            ...(filters.categoryCode ? { categoryCode: filters.categoryCode } : {}),
            sort: filters.sort,
          }).toString()}`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          }
        );

        const data = (await response.json().catch(() => ({}))) as
          | OperationsIntakeReportsResponse
          | { error?: { message?: string }; message?: string };

        if (!response.ok) {
          let errMsg = "Could not load intake reports.";

          if ("error" in data && data.error?.message) {
            errMsg = data.error.message;
          } else if ("message" in data && typeof data.message === "string") {
            errMsg = data.message;
          }

          setError(errMsg);
          setReports([]);
          return;
        }

        const responseData = data as OperationsIntakeReportsResponse;

        setReports(responseData.intake_reports);
        setPagination(responseData.pagination);
      } catch {
        setError("Unexpected error while loading reports.");
        setReports([]);
      } finally {
        setLoading(false);
      }
    },
    [filters, router]
  );

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
    void loadReports();
  }, [isLoadingSession, loadReports]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const formatDate = (iso: string | null) => {
    if (!iso) return "-";

    const d = new Date(iso);

    if (Number.isNaN(d.getTime())) return iso;

    return d.toLocaleString();
  };

  if (isLoadingSession) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    );
  }

  return (
    <DashboardLayout
      title="Intake Reports"
      subtitle="Operations queue for intake reports pending classification"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              Intake Reports
            </h1>

            <p className="mt-1 text-sm text-gray-600">
              Total: {pagination.total} | Showing: {reports.length}
            </p>
          </div>

          <div className="flex gap-2">
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
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
            <p>{error}</p>
          </div>
        )}

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">Filters</h2>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 md:grid-cols-5">
              <select
                value={filters.intake_status}
                onChange={(e) =>
                  setFilters((current) => ({
                    ...current,
                    intake_status: e.target.value,
                  }))
                }
                className="h-[42px] rounded-lg border border-gray-300 bg-white px-3 text-sm text-gray-900"
              >
                <option value="">All statuses</option>
                <option value="received">Received</option>
                <option value="under_review">Under review</option>
                <option value="linked_to_case">Linked to case</option>
                <option value="linked_to_incident">Linked to incident</option>
              </select>
              <select
                value={filters.urgency_type}
                onChange={(e) =>
                  setFilters((current) => ({
                    ...current,
                    urgency_type: e.target.value,
                  }))
                }
                className="h-[42px] rounded-lg border border-gray-300 bg-white px-3 text-sm text-gray-900"
              >
                <option value="">All urgency</option>
                <option value="unknown">Unknown</option>
                <option value="non_emergency">Non-emergency</option>
                <option value="emergency">Emergency</option>
              </select>
              <select
                value={filters.categoryCode}
                onChange={(e) =>
                  setFilters((current) => ({
                    ...current,
                    categoryCode: e.target.value,
                  }))
                }
                className="h-[42px] rounded-lg border border-gray-300 bg-white px-3 text-sm text-gray-900"
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
              <select
                value={filters.sort}
                onChange={(e) =>
                  setFilters((current) => ({ ...current, sort: e.target.value }))
                }
                className="h-[42px] rounded-lg border border-gray-300 bg-white px-3 text-sm text-gray-900"
              >
                <option value="reported_at_desc">Newest first</option>
                <option value="reported_at_asc">Oldest first</option>
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
            <h2 className="text-lg font-semibold text-gray-900">
              Reports Queue
            </h2>
          </CardHeader>

          <CardContent className="p-0">
            {loading && reports.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-gray-500">
                Loading reports...
              </div>
            ) : reports.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-gray-500">
                No intake reports found.
              </div>
            ) : (
              <ul className="divide-y divide-gray-100">
                {reports.map((report) => (
                  <li
                    key={report.public_uuid}
                    className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="inline-flex rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800">
                          {report.intake_status}
                        </span>

                        <span className="inline-flex rounded-full bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">
                          {report.urgency_type}
                        </span>

                        <span className="inline-flex flex-col text-xs text-gray-500">
                          <span className="text-sm font-bold uppercase tracking-wide text-gray-600">
                            Report ID
                          </span>
                          <span>{report.report_code}</span>
                        </span>
                      </div>

                      <p className="mt-1 font-medium text-gray-900">
                        {report.summary}
                      </p>

                      <p className="mt-0.5 text-sm text-gray-600">
                        <span className="font-medium text-gray-700">
                          {report.category_code}
                        </span>

                        <span className="mx-1.5 text-gray-300">|</span>

                        <span className="text-gray-500">
                          Reported: {formatDate(report.reported_at)}
                        </span>
                      </p>
                    </div>

                    <div className="flex shrink-0 gap-2">
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
