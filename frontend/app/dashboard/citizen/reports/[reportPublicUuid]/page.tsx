"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { apiJson } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { IntakeReport, IntakeReportListResponse } from "@/types/intake";

function formatDate(value: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function DetailRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-600">{label}</dt>
      <dd className="mt-1 break-words text-sm text-gray-900">{value || "-"}</dd>
    </div>
  );
}

export default function CitizenReportDetailPage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;
  const isChecking = useAuthGuard(["citizen"]);
  const [reports, setReports] = useState<IntakeReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const report = useMemo(
    () => reports.find((item) => item.public_uuid === reportPublicUuid) ?? null,
    [reportPublicUuid, reports],
  );

  useEffect(() => {
    if (isChecking) return;

    async function loadReports() {
      setLoading(true);
      setError("");
      try {
        const data = await apiJson<IntakeReportListResponse>("/intake/reports/my");
        setReports(data.reports ?? []);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load report.");
      } finally {
        setLoading(false);
      }
    }

    void loadReports();
  }, [isChecking]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <div className="flex min-h-screen items-center justify-center">Loading...</div>;
  }

  return (
    <DashboardLayout
      title="Report Details"
      subtitle={`Report ${report?.report_code ?? reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <Button
          type="button"
          variant="secondary"
          onClick={() => router.push("/dashboard/citizen/reports")}
        >
          Back to My Reports
        </Button>

        {error && <ErrorAlert message={error} />}

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">Report Snapshot</h2>
          </CardHeader>
          <CardContent>
            {loading ? (
              <LoadingSkeleton lines={6} />
            ) : !report ? (
              <p className="text-sm text-gray-600">Report not found in your account.</p>
            ) : (
              <div className="space-y-6">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="text-sm font-bold uppercase tracking-wide text-gray-600">
                      Report ID
                    </p>
                    <p className="mt-0.5 text-sm text-gray-600">
                      {report.report_code}
                    </p>
                    <h3 className="mt-1 text-xl font-semibold text-gray-900">
                      {report.summary}
                    </h3>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge tone={report.intake_status}>
                      {formatBadgeLabel(report.intake_status)}
                    </Badge>
                    <Badge tone={report.urgency_type}>
                      {formatBadgeLabel(report.urgency_type)}
                    </Badge>
                  </div>
                </div>

                <p className="whitespace-pre-wrap text-sm leading-6 text-gray-700">
                  {report.description || "No description provided."}
                </p>

                <dl className="grid gap-4 sm:grid-cols-2">
                  <DetailRow label="Category" value={formatBadgeLabel(report.category_code)} />
                  <DetailRow label="Location" value={report.location_text} />
                  <DetailRow label="Reported At" value={formatDate(report.reported_at)} />
                  <DetailRow label="Created At" value={formatDate(report.created_at)} />
                  <DetailRow label="Final Disposition" value={report.final_disposition} />
                  <DetailRow label="Public UUID" value={report.public_uuid} />
                </dl>

                {report.incident_code && (
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                    <h3 className="text-sm font-semibold text-gray-900">
                      Linked Incident
                    </h3>
                    <p className="mt-1 text-sm text-gray-700">
                      {report.incident_code} -{" "}
                      {formatBadgeLabel(report.incident_status_code)}
                    </p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
