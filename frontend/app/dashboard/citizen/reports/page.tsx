"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession } from "@/lib/auth-store";
import type { IntakeReport, IntakeReportListResponse } from "@/types/intake";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

function formatDate(value: string | null): string {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function getReportStatus(report: IntakeReport): string {
  return report.incident_status_code ?? report.intake_status;
}

function getStatusColor(status: string): string {
  switch (status) {
    case "resolved":
    case "closed":
      return "bg-green-50 text-green-700";
    case "cancelled":
    case "false_report":
    case "duplicate":
      return "bg-gray-100 text-gray-700";
    case "reported":
    case "classified":
    case "in_progress":
    case "linked_to_incident":
      return "bg-yellow-50 text-yellow-700";
    default:
      return "bg-blue-50 text-blue-700";
  }
}

export default function CitizenReportsPage() {
  const router = useRouter();
  const [reports, setReports] = useState<IntakeReport[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  useEffect(() => {
    const accessToken = localStorage.getItem("accessToken");
    if (!accessToken) {
      router.push("/auth/login");
      return;
    }

    const loadReports = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const response = await fetch(`${API_BASE}/intake/reports/my`, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        });

        const data = (await response.json().catch(() => ({}))) as
          | IntakeReportListResponse
          | { error?: { message?: string }; message?: string };

        if (!response.ok) {
          let errMsg = "Failed to load reports.";

          if ("error" in data && data.error?.message) {
            errMsg = data.error.message;
          } else if ("message" in data && typeof data.message === "string") {
            errMsg = data.message;
          }

          setError(errMsg);
          return;
        }

        setReports((data as IntakeReportListResponse).reports ?? []);
      } catch {
        setError("Unexpected error while loading your reports.");
      } finally {
        setIsLoading(false);
      }
    };

    loadReports();
  }, [router]);

  return (
    <DashboardLayout
      title="My Reports"
      subtitle="View incidents you reported"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
          <Button
            variant="secondary"
            onClick={() => router.push("/dashboard/citizen")}
          >
            Back to Dashboard
          </Button>
          <Button onClick={() => router.push("/dashboard/citizen/report-new")}>
            Report New Incident
          </Button>
        </div>

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Reported Incidents
            </h2>
          </CardHeader>
          <CardContent>
            {isLoading && (
              <p className="text-sm text-gray-600">Loading your reports...</p>
            )}

            {error && (
              <div className="rounded-lg bg-red-50 p-3 text-sm text-red-700">
                {error}
              </div>
            )}

            {!isLoading && !error && reports.length === 0 && (
              <p className="text-sm text-gray-600">No reports found yet.</p>
            )}

            {!isLoading && !error && reports.length > 0 && (
              <div className="space-y-3">
                {reports.map((report) => (
                  <div
                    key={report.public_uuid}
                    className="rounded-lg border border-gray-200 bg-white p-4"
                  >
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <p className="text-sm font-bold uppercase tracking-wide text-gray-600">
                          Report ID
                        </p>

                        <p className="mt-0.5 text-sm text-gray-600">
                          {report.report_code}
                        </p>
                        <h3 className="font-medium text-gray-900">
                          {report.summary}
                        </h3>
                      </div>
                      <span
                        className={`rounded-full px-3 py-1 text-xs font-medium ${getStatusColor(getReportStatus(report))}`}
                      >
                        {getReportStatus(report)}
                      </span>
                    </div>

                    <div className="mt-3 grid gap-2 text-sm text-gray-600 sm:grid-cols-2">
                      <p>
                        <span className="font-medium text-gray-800">
                          Category:
                        </span>{" "}
                        {report.category_code}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">
                          Urgency:
                        </span>{" "}
                        {report.urgency_type}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">
                          Location:
                        </span>{" "}
                        {report.location_text || "-"}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">
                          Created:
                        </span>{" "}
                        {formatDate(report.created_at)}
                      </p>
                      {report.incident_code && (
                        <p>
                          <span className="font-medium text-gray-800">
                            Incident:
                          </span>{" "}
                          {report.incident_code}
                        </p>
                      )}
                      {report.incident_resolved_at && (
                        <p>
                          <span className="font-medium text-gray-800">
                            Resolved:
                          </span>{" "}
                          {formatDate(report.incident_resolved_at)}
                        </p>
                      )}
                    </div>
                    <div className="mt-4">
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() =>
                          router.push(
                            `/dashboard/citizen/reports/${report.public_uuid}`,
                          )
                        }
                      >
                        View Details
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
