"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, FileText, MapPin } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { clearAuthSession } from "@/lib/auth-store";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  formatIncidentStatus,
  formatIncidentStatusContext,
  mapIncidentsByIntakeUuid,
} from "@/lib/incident-status";
import { apiGet } from "@/lib/api";
import { formatReportStatus, getReportStatusTone } from "@/lib/report-status";
import { sortNewestFirst } from "@/lib/sort";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { CitizenIncident } from "@/types/citizen-incident";
import type {
  IntakeLocation,
  IntakeReport,
  IntakeReportListResponse,
} from "@/types/intake";

function getReportStatus(report: IntakeReport): string {
  return report.intake_status;
}

function formatLocation(location: IntakeLocation | null | undefined) {
  if (!location) return null;

  return (
    location.address_text ||
    location.place_name ||
    "Map location selected"
  );
}

export default function CitizenReportsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [reports, setReports] = useState<IntakeReport[]>([]);
  const [incidents, setIncidents] = useState<CitizenIncident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [incidentError, setIncidentError] = useState<string | null>(null);

  const incidentsByIntakeUuid = mapIncidentsByIntakeUuid(incidents);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  useEffect(() => {
    if (isChecking) return;

    const loadReports = async () => {
      setIsLoading(true);
      setError(null);
      setIncidentError(null);

      try {
        const [reportsResult, incidentsResult] = await Promise.allSettled([
          apiGet<IntakeReportListResponse>("/intake/reports/my"),
          getMyIncidents(),
        ]);

        if (reportsResult.status === "fulfilled") {
          setReports(
            sortNewestFirst(reportsResult.value.reports ?? [], (report) => [
              report.reported_at,
              report.created_at,
              report.updated_at,
            ]),
          );
        } else {
          throw reportsResult.reason;
        }

        if (incidentsResult.status === "fulfilled") {
          setIncidents(incidentsResult.value.incidents ?? []);
        } else {
          setIncidents([]);
          setIncidentError(
            incidentsResult.reason instanceof Error
              ? incidentsResult.reason.message
              : "Could not load linked emergency incident status.",
          );
        }
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unexpected error while loading your reports.",
        );
      } finally {
        setIsLoading(false);
      }
    };

    void loadReports();
  }, [isChecking]);

  if (isChecking) {
    return <PageLoading label="Loading reports" />;
  }

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
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <FileText className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Reported Incidents
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  Newest reports appear first.
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {isLoading && (
              <p className="text-sm text-gray-600">Loading your reports...</p>
            )}

            {error && (
              <ErrorAlert message={error} />
            )}

            {!error && incidentError ? (
              <div className="mb-4">
                <ErrorAlert message={incidentError} />
              </div>
            ) : null}

            {!isLoading && !error && reports.length === 0 && (
              <EmptyState
                title="No reports yet"
                description="Submitted citizen reports will show here with status and location details."
                icon={<FileText className="h-6 w-6" aria-hidden />}
                action={
                  <Button
                    type="button"
                    onClick={() => router.push("/dashboard/citizen/report-new")}
                  >
                    Report New Incident
                  </Button>
                }
              />
            )}

            {!isLoading && !error && reports.length > 0 && (
              <div className="grid gap-4">
                {reports.map((report) => {
                  const linkedIncident =
                    report.intake_status === "linked_to_incident"
                      ? incidentsByIntakeUuid.get(report.public_uuid)
                      : undefined;

                  return (
                    <div
                      key={report.public_uuid}
                      className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm"
                    >
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div>
                          <p className="text-xs font-bold uppercase tracking-wide text-[#006747]">
                            {report.report_code}
                          </p>
                          <h3 className="mt-1 text-lg font-semibold text-gray-900">
                            {report.summary}
                          </h3>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge tone={getReportStatusTone(getReportStatus(report))}>
                            {formatReportStatus(getReportStatus(report))}
                          </Badge>
                          {linkedIncident ? (
                            <Badge tone={linkedIncident.status_code}>
                              {formatIncidentStatusContext(linkedIncident.status_code)}
                            </Badge>
                          ) : null}
                          <Badge tone={report.urgency_type}>
                            {formatBadgeLabel(report.urgency_type)}
                          </Badge>
                        </div>
                      </div>

                      <div className="mt-4 grid gap-3 text-sm text-gray-600 sm:grid-cols-2">
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
                          Status:
                        </span>{" "}
                        {formatReportStatus(report.intake_status)}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">
                          Final Disposition:
                        </span>{" "}
                        {formatBadgeLabel(report.final_disposition)}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">
                          Reported:
                        </span>{" "}
                        {formatBangladeshTime(report.reported_at)}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">
                          Created:
                        </span>{" "}
                        {formatBangladeshTime(report.created_at)}
                      </p>
                      {report.updated_at ? (
                        <p>
                          <span className="font-medium text-gray-800">
                            Updated:
                          </span>{" "}
                          {formatBangladeshTime(report.updated_at)}
                        </p>
                      ) : null}
                      <div className="sm:col-span-2">
                        <div className="flex gap-2 rounded-2xl bg-[#EFF6FF] px-3 py-2">
                          <MapPin
                            className="mt-0.5 h-4 w-4 shrink-0 text-[#006747]"
                            aria-hidden
                          />
                          <p>
                            <span className="font-medium text-gray-800">
                              Location:
                            </span>{" "}
                            {formatLocation(report.location) ||
                              report.location_text ||
                              "-"}
                          </p>
                        </div>
                      </div>
                    </div>
                    {report.intake_status === "linked_to_incident" ? (
                      <div className="mt-4 rounded-2xl border border-[#DA291C]/15 bg-red-50 px-4 py-3 text-sm text-red-900">
                        <p className="font-semibold">Linked To Incident</p>
                        {linkedIncident ? (
                          <p className="mt-1">
                            {linkedIncident.incident_code} is currently{" "}
                            {formatIncidentStatus(linkedIncident.status_code)}.
                          </p>
                        ) : (
                          <p className="mt-1">
                            This report has been linked to an emergency incident.
                          </p>
                        )}
                      </div>
                    ) : null}
                    <div className="mt-5 flex flex-wrap gap-2">
                      <Button
                        type="button"
                        size="sm"
                        onClick={() =>
                          router.push(
                            `/dashboard/citizen/reports/${report.public_uuid}`,
                          )
                        }
                      >
                        View Details
                        <ArrowRight className="h-4 w-4" aria-hidden />
                      </Button>
                      {report.intake_status === "linked_to_incident" ? (
                        <Button
                          type="button"
                          size="sm"
                          variant="secondary"
                          onClick={() =>
                            router.push(
                              linkedIncident
                                ? `/dashboard/citizen/incidents#${linkedIncident.public_uuid}`
                                : "/dashboard/citizen/incidents",
                            )
                          }
                        >
                          View Incident
                          <ArrowRight className="h-4 w-4" aria-hidden />
                        </Button>
                      ) : null}
                    </div>
                  </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
