"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowRight } from "lucide-react";
import {
  CitizenLocationPill,
  CitizenMetaItem,
  CitizenPageContent,
  CitizenRecordCard,
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { LocationSummary } from "@/components/location/LocationSummary";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { apiGet } from "@/lib/api";
import { sortNewestFirst } from "@/lib/sort";
import {
  formatIncidentCategory,
  formatIncidentStatus,
  isTerminalIncident,
} from "@/lib/incident-status";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { CitizenIncident } from "@/types/citizen-incident";
import type { IntakeLocation, IntakeReportListResponse } from "@/types/intake";

function getResponseSummary(incident: CitizenIncident) {
  if (incident.description?.trim()) {
    return incident.description.trim();
  }

  return `Emergency response status: ${formatIncidentStatus(incident.status_code)}.`;
}

export default function CitizenIncidentsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [incidents, setIncidents] = useState<CitizenIncident[]>([]);
  const [reportSummariesByIntakeUuid, setReportSummariesByIntakeUuid] = useState<
    Map<string, string>
  >(new Map());
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  useEffect(() => {
    if (isChecking) return;

    const loadIncidents = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const [incidentsResult, reportsResult] = await Promise.allSettled([
          getMyIncidents(),
          apiGet<IntakeReportListResponse>("/intake/reports/my"),
        ]);

        if (incidentsResult.status === "fulfilled") {
          setIncidents(
            sortNewestFirst(incidentsResult.value.incidents ?? [], (incident) => [
              incident.last_updated,
              incident.reported_at,
              incident.created_at,
            ]),
          );
        } else {
          throw incidentsResult.reason;
        }

        if (reportsResult.status === "fulfilled") {
          const nextMap = new Map<string, string>();
          for (const report of reportsResult.value.reports ?? []) {
            nextMap.set(report.public_uuid, report.summary);
          }
          setReportSummariesByIntakeUuid(nextMap);
        } else {
          setReportSummariesByIntakeUuid(new Map());
        }
      } catch (err) {
        console.error("Failed to load citizen incidents", err);
        setError(
          getCitizenFriendlyError(
            err,
            "We could not load your emergency responses right now. Please try again.",
          ),
        );
      } finally {
        setIsLoading(false);
      }
    };

    void loadIncidents();
  }, [isChecking]);

  const incidentsWithSummaries = useMemo(
    () =>
      incidents.map((incident) => ({
        incident,
        linkedReportSummary:
          reportSummariesByIntakeUuid.get(incident.intake_public_uuid) ??
          "Your submitted report",
      })),
    [incidents, reportSummariesByIntakeUuid],
  );

  if (isChecking) {
    return <PageLoading label="Loading emergency responses" />;
  }

  return (
    <DashboardLayout
      title="Emergency Response"
      subtitle="Track emergency responses linked to your reports."
      onLogout={handleLogout}
    >
      <CitizenPageContent>
        <CitizenSectionCard
          title="Your Emergency Responses"
          subtitle="Follow active and completed emergency responses connected to your reports."
          icon={<AlertTriangle className="h-5 w-5" aria-hidden />}
        >
          {isLoading ? (
            <p className="text-sm text-[#42547A]">Loading emergency responses...</p>
          ) : null}

          {error ? <ErrorAlert message={error} /> : null}

          {!isLoading && !error && incidents.length === 0 ? (
            <EmptyState
              title="No emergency responses yet."
              description="When a report is connected to an emergency response, you can track it here."
              icon={<AlertTriangle className="h-6 w-6" aria-hidden />}
            />
          ) : null}

          {!isLoading && !error && incidents.length > 0 ? (
            <div className="grid gap-4">
              {incidentsWithSummaries.map(({ incident, linkedReportSummary }) => {
                const isFinal = isTerminalIncident(incident.status_code);
                const responseSummary = getResponseSummary(incident);

                return (
                  <CitizenRecordCard
                    id={incident.public_uuid}
                    key={incident.public_uuid}
                  >
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div className="min-w-0">
                            <h3 className="break-words text-lg font-semibold text-slate-950">
                              {incident.title || "Emergency response"}
                            </h3>
                            <p className="mt-2 line-clamp-2 text-sm leading-6 text-[#42547A]">
                              {responseSummary}
                            </p>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <Badge tone={incident.status_code}>
                              {formatIncidentStatus(incident.status_code)}
                            </Badge>
                            {incident.severity_code ? (
                              <Badge tone={incident.severity_code}>
                                {formatBadgeLabel(incident.severity_code)}
                              </Badge>
                            ) : null}
                          </div>
                        </div>

                        <div className="mt-4 grid gap-3 sm:grid-cols-2">
                          <CitizenMetaItem
                            label="Your report"
                            value={linkedReportSummary}
                          />
                          <CitizenMetaItem
                            label="Category"
                            value={formatIncidentCategory(incident.category_code)}
                          />
                          <CitizenMetaItem
                            label="Reported"
                            value={formatBangladeshTime(incident.reported_at)}
                          />
                          <CitizenMetaItem
                            label="Last updated"
                            value={formatBangladeshTime(incident.last_updated)}
                          />
                          <div className="sm:col-span-2">
                            <CitizenLocationPill>
                              {incident.location ? (
                                <LocationSummary location={incident.location} />
                              ) : (
                                incident.location_text || "-"
                              )}
                            </CitizenLocationPill>
                          </div>
                        </div>
                      </div>

                      <div className="flex w-full shrink-0 flex-col gap-2 lg:w-56">
                        <Button
                          type="button"
                          size="sm"
                          className="w-full justify-between"
                          onClick={() =>
                            router.push(
                              `/dashboard/citizen/incidents/${incident.public_uuid}`,
                            )
                          }
                        >
                          View Response Details
                          <ArrowRight className="h-4 w-4" aria-hidden />
                        </Button>
                        {isFinal ? (
                          <p className="text-center text-xs text-[#42547A]">
                            This response is complete and view-only.
                          </p>
                        ) : null}
                      </div>
                    </div>
                  </CitizenRecordCard>
                );
              })}
            </div>
          ) : null}
        </CitizenSectionCard>
      </CitizenPageContent>
    </DashboardLayout>
  );
}
