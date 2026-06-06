"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, FileText } from "lucide-react";
import {
  CitizenLocationPill,
  CitizenMetaItem,
  CitizenRecordCard,
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
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
          console.error(
            "Failed to load linked emergency incidents for reports page",
            incidentsResult.reason,
          );
          setIncidents([]);
          setIncidentError(
            "We could not load linked incident updates for these reports.",
          );
        }
      } catch (err) {
        console.error("Failed to load citizen reports", err);
        setError(
          getCitizenFriendlyError(
            err,
            "We could not load your reports right now. Please try again.",
          ),
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
      subtitle="Track reports you submitted to NIERS."
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <CitizenSectionCard
          title="Your Reports"
          subtitle="Newest reports appear first."
          icon={<FileText className="h-5 w-5" aria-hidden />}
        >
            {isLoading && (
              <p className="text-sm text-[#42547A]">Loading your reports...</p>
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
                title="No reports submitted yet."
                description="Reports you submit to NIERS will appear here with status and location details."
                icon={<FileText className="h-6 w-6" aria-hidden />}
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
                    <CitizenRecordCard
                      key={report.public_uuid}
                    >
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0">
                          <p className="text-xs font-bold uppercase tracking-wide text-[#006747]">
                            {report.report_code}
                          </p>
                          <h3 className="mt-1 break-words text-lg font-semibold text-slate-950">
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
                        </div>
                      </div>

                      <div className="mt-4 grid gap-3 sm:grid-cols-2">
                        <CitizenMetaItem
                          label="Category"
                          value={report.category_code}
                        />
                        <CitizenMetaItem
                          label="Reported"
                          value={formatBangladeshTime(report.reported_at)}
                        />
                        <div className="sm:col-span-2">
                          <CitizenLocationPill>
                            {formatLocation(report.location) ||
                              report.location_text ||
                              "-"}
                          </CitizenLocationPill>
                        </div>
                    </div>
                    {report.intake_status === "linked_to_incident" ? (
                      <div className="mt-4 rounded-xl border border-[#DA291C]/15 bg-red-50 px-4 py-3 text-sm text-red-900">
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
                  </CitizenRecordCard>
                  );
                })}
              </div>
            )}
        </CitizenSectionCard>
      </div>
    </DashboardLayout>
  );
}
