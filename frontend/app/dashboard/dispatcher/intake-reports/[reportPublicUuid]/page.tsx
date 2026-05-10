"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession, getValidAccessToken } from "@/lib/auth-store";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportResponse,
} from "@/types/operations-intake";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

function formatLabel(value: string | null | undefined) {
  if (!value) return "-";
  return value.replace(/_/g, " ");
}

function formatDate(iso: string | null) {
  if (!iso) return "-";

  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;

  return d.toLocaleString();
}

function getStatusColor(status: string) {
  switch (status) {
    case "received":
      return "bg-blue-100 text-blue-800";
    case "under_review":
      return "bg-yellow-100 text-yellow-800";
    case "linked_to_case":
      return "bg-indigo-100 text-indigo-800";
    case "linked_to_incident":
      return "bg-red-100 text-red-800";
    case "closed":
      return "bg-green-100 text-green-800";
    case "duplicate":
    case "false_report":
      return "bg-gray-100 text-gray-800";
    default:
      return "bg-gray-100 text-gray-800";
  }
}

function getUrgencyColor(urgency: string) {
  switch (urgency) {
    case "emergency":
      return "bg-red-100 text-red-800";
    case "non_emergency":
      return "bg-green-100 text-green-800";
    case "unknown":
      return "bg-yellow-100 text-yellow-800";
    default:
      return "bg-gray-100 text-gray-800";
  }
}

function Badge({
  children,
  className,
}: {
  children: ReactNode;
  className: string;
}) {
  return (
    <span
      className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium capitalize ${className}`}
    >
      {children}
    </span>
  );
}

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-600">{label}</dt>
      <dd className="mt-1 break-words text-sm text-gray-900">{children}</dd>
    </div>
  );
}

export default function IntakeReportDetailPage() {
  const params = useParams();
  const router = useRouter();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [report, setReport] = useState<OperationsIntakeReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoadingSession, setIsLoadingSession] = useState(true);

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  const loadReport = useCallback(async () => {
    const accessToken = getValidAccessToken();

    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${API_BASE}/operations/intake-reports/${reportPublicUuid}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      );

      const data = (await response.json().catch(() => ({}))) as
        | OperationsIntakeReportResponse
        | { error?: { message?: string }; message?: string };

      if (!response.ok) {
        let errMsg = "Could not load intake report.";

        if ("error" in data && data.error?.message) {
          errMsg = data.error.message;
        } else if ("message" in data && typeof data.message === "string") {
          errMsg = data.message;
        }

        setError(errMsg);
        setReport(null);
        return;
      }

      setReport((data as OperationsIntakeReportResponse).intake_report);
    } catch {
      setError("Unexpected error while loading report.");
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [reportPublicUuid, redirectToLogin]);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    const accessToken = getValidAccessToken();

    if (!sessionUser || !accessToken) {
      redirectToLogin();
      return;
    }

    setIsLoadingSession(false);
  }, [redirectToLogin]);

  useEffect(() => {
    if (isLoadingSession || !reportPublicUuid) return;
    void loadReport();
  }, [isLoadingSession, reportPublicUuid, loadReport]);

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

  return (
    <DashboardLayout
      title="Intake Report Details"
      subtitle={`Report ${report?.report_code || reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex flex-wrap items-center gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={() => router.push("/dashboard/dispatcher/intake-reports")}
          >
            &larr; Back to Reports
          </Button>

          <Button
            type="button"
            variant="secondary"
            onClick={() => void loadReport()}
            disabled={loading}
          >
            {loading ? "Loading..." : "Refresh"}
          </Button>

          {report && !report.has_incident ? (
            <Button
              type="button"
              onClick={() =>
                router.push(
                  `/dashboard/dispatcher/intake-reports/${report.public_uuid}/promote/emergency`,
                )
              }
            >
              Promote to Emergency
            </Button>
          ) : null}
        </div>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
            <p>{error}</p>
          </div>
        )}

        {loading && !report ? (
          <div className="text-center text-sm text-gray-500">
            Loading report...
          </div>
        ) : null}

        {!loading && !report && !error ? (
          <div className="text-center text-sm text-gray-500">
            Intake report was not found.
          </div>
        ) : null}

        {report ? (
          <div className="grid gap-6 lg:grid-cols-3">
            <Card className="shadow-md lg:col-span-2">
              <CardHeader>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-500">
                      {report.report_code}
                    </p>
                    <h2 className="mt-1 text-xl font-semibold text-gray-900">
                      {report.summary || "(No summary)"}
                    </h2>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Badge className={getStatusColor(report.intake_status)}>
                      {formatLabel(report.intake_status)}
                    </Badge>
                    <Badge className={getUrgencyColor(report.urgency_type)}>
                      {formatLabel(report.urgency_type)}
                    </Badge>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-gray-900">
                    Description
                  </h3>
                  <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                    {report.description?.trim() || "No description provided."}
                  </p>
                </div>

                {report.final_disposition ? (
                  <div className="rounded-lg border border-gray-200 bg-gray-50 p-4">
                    <h3 className="text-sm font-semibold text-gray-900">
                      Final Disposition
                    </h3>
                    <p className="mt-1 text-sm text-gray-700">
                      {formatLabel(report.final_disposition)}
                    </p>
                  </div>
                ) : null}
              </CardContent>
            </Card>

            <Card className="shadow-md">
              <CardHeader>
                <h2 className="text-lg font-semibold text-gray-900">
                  Operations Snapshot
                </h2>
              </CardHeader>

              <CardContent>
                <dl className="space-y-4">
                  <DetailRow label="Reporter User ID">
                    {report.reporter_user_id}
                  </DetailRow>
                  <DetailRow label="Category">
                    {formatLabel(report.category_code)}
                  </DetailRow>
                  <DetailRow label="Channel">
                    {formatLabel(report.channel_code)}
                  </DetailRow>
                  <DetailRow label="Service Case">
                    {report.has_service_case ? "Linked" : "Not linked"}
                  </DetailRow>
                  <DetailRow label="Incident">
                    {report.has_incident ? "Linked" : "Not linked"}
                  </DetailRow>
                  <DetailRow label="Public UUID">{report.public_uuid}</DetailRow>
                </dl>
              </CardContent>
            </Card>

            <Card className="shadow-md lg:col-span-3">
              <CardHeader>
                <h2 className="text-lg font-semibold text-gray-900">
                  Timeline
                </h2>
              </CardHeader>

              <CardContent>
                <dl className="grid gap-4 sm:grid-cols-3">
                  <DetailRow label="Reported At">
                    {formatDate(report.reported_at)}
                  </DetailRow>
                  <DetailRow label="Created At">
                    {formatDate(report.created_at)}
                  </DetailRow>
                  <DetailRow label="Updated At">
                    {formatDate(report.updated_at)}
                  </DetailRow>
                </dl>
              </CardContent>
            </Card>
          </div>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
