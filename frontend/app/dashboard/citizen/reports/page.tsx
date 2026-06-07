"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, FileText } from "lucide-react";
import {
  CitizenLocationPill,
  CitizenMetaItem,
  CitizenPageContent,
  CitizenRecordCard,
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
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
  isActiveIncident,
  mapIncidentsByIntakeUuid,
} from "@/lib/incident-status";
import { apiGet } from "@/lib/api";
import {
  formatReportStatus,
  getReportStatusTone,
  mapServiceCasesByIntakeUuid,
} from "@/lib/report-status";
import { sortNewestFirst } from "@/lib/sort";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { CitizenIncident } from "@/types/citizen-incident";
import type {
  IntakeLocation,
  IntakeReport,
  IntakeReportListResponse,
} from "@/types/intake";
import type {
  CitizenServiceCase,
  CitizenServiceCaseListResponse,
} from "@/types/service-case";

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

function getCitizenReportStatusLabel(status: string) {
  if (status === "linked_to_incident") return "Linked to Incident";
  if (status === "linked_to_case") return "Linked to Service Case";
  return formatReportStatus(status);
}

function getPrimaryReportAction(
  report: IntakeReport,
  linkedIncident: CitizenIncident | undefined,
  linkedServiceCase: CitizenServiceCase | undefined,
) {
  if (report.intake_status === "linked_to_incident" && linkedIncident) {
    return {
      label: "Track Emergency Response",
      href: `/dashboard/citizen/incidents/${linkedIncident.public_uuid}`,
    };
  }

  if (report.intake_status === "linked_to_case" && linkedServiceCase) {
    return {
      label: "Open Service Case",
      href: `/dashboard/citizen/service-cases/${linkedServiceCase.public_uuid}`,
    };
  }

  return {
    label: "View Report Status",
    href: `/dashboard/citizen/reports/${report.public_uuid}`,
  };
}

export default function CitizenReportsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [reports, setReports] = useState<IntakeReport[]>([]);
  const [incidents, setIncidents] = useState<CitizenIncident[]>([]);
  const [serviceCases, setServiceCases] = useState<CitizenServiceCase[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [incidentError, setIncidentError] = useState<string | null>(null);

  const incidentsByIntakeUuid = mapIncidentsByIntakeUuid(incidents);
  const serviceCasesByIntakeUuid = mapServiceCasesByIntakeUuid(serviceCases);

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
        const [reportsResult, incidentsResult, serviceCasesResult] =
          await Promise.allSettled([
            apiGet<IntakeReportListResponse>("/intake/reports/my"),
            getMyIncidents(),
            apiGet<CitizenServiceCaseListResponse>(
              "/intake/reports/my/service-cases",
            ),
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
            "We could not load linked emergency response updates for these reports.",
          );
        }

        if (serviceCasesResult.status === "fulfilled") {
          setServiceCases(serviceCasesResult.value.service_cases ?? []);
        } else {
          setServiceCases([]);
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
      <CitizenPageContent>
        <CitizenSectionCard
          title="Your Reports"
          subtitle="Newest reports appear first."
          icon={<FileText className="h-5 w-5" aria-hidden />}
        >
          {isLoading && (
            <p className="text-sm text-[#42547A]">Loading your reports...</p>
          )}

          {error && <ErrorAlert message={error} />}

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
                const linkedServiceCases =
                  serviceCasesByIntakeUuid.get(report.public_uuid) ?? [];
                const linkedServiceCase = linkedServiceCases[0];
                const primaryAction = getPrimaryReportAction(
                  report,
                  linkedIncident,
                  linkedServiceCase,
                );
                const showIncidentModule =
                  report.intake_status === "linked_to_incident" && linkedIncident;

                return (
                  <CitizenRecordCard key={report.public_uuid}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div className="min-w-0">
                            <h3 className="break-words text-lg font-semibold text-slate-950">
                              {report.summary}
                            </h3>
                            <p className="mt-1 text-sm text-[#42547A]">
                              Reported {formatBangladeshTime(report.reported_at)}
                            </p>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <Badge tone={getReportStatusTone(getReportStatus(report))}>
                              {getCitizenReportStatusLabel(getReportStatus(report))}
                            </Badge>
                            {linkedIncident && isActiveIncident(linkedIncident) ? (
                              <Badge tone={linkedIncident.status_code}>
                                Incident in Progress
                              </Badge>
                            ) : linkedIncident ? (
                              <Badge tone={linkedIncident.status_code}>
                                {formatIncidentStatusContext(linkedIncident.status_code)}
                              </Badge>
                            ) : null}
                          </div>
                        </div>

                        <div className="mt-4 grid gap-3 sm:grid-cols-2">
                          <CitizenMetaItem
                            label="Category"
                            value={formatBadgeLabel(report.category_code)}
                          />
                          <CitizenMetaItem
                            label="Submitted"
                            value={formatBangladeshTime(report.created_at)}
                          />
                          <div className="sm:col-span-2">
                            <CitizenLocationPill>
                              {formatLocation(report.location) ||
                                report.location_text ||
                                "-"}
                            </CitizenLocationPill>
                          </div>
                        </div>
                      </div>

                      <div className="flex w-full shrink-0 flex-col gap-3 lg:w-72">
                        {showIncidentModule ? (
                          <div className="rounded-xl border border-slate-200/80 bg-[#F6F9FE] px-4 py-3">
                            <p className="text-sm font-semibold text-[#002D62]">
                              Emergency response linked
                            </p>
                            <p className="mt-1 text-sm text-[#42547A]">
                              Your report has been connected to an active emergency
                              response.
                            </p>
                            <p className="mt-2 text-sm font-medium text-slate-800">
                              {isActiveIncident(linkedIncident)
                                ? "Response currently in progress."
                                : `Response status: ${formatIncidentStatus(linkedIncident.status_code)}.`}
                            </p>
                          </div>
                        ) : null}

                        <Button
                          type="button"
                          size="sm"
                          className="w-full justify-between"
                          onClick={() => router.push(primaryAction.href)}
                        >
                          {primaryAction.label}
                          <ArrowRight className="h-4 w-4" aria-hidden />
                        </Button>
                      </div>
                    </div>
                  </CitizenRecordCard>
                );
              })}
            </div>
          )}
        </CitizenSectionCard>
      </CitizenPageContent>
    </DashboardLayout>
  );
}
