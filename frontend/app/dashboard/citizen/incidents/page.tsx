"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowRight, CheckCircle2, FileText, MapPin } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { sortNewestFirst } from "@/lib/sort";
import {
  formatIncidentStatus,
  isActiveIncident,
  isFinalIncident,
  isResolvedIncident,
} from "@/lib/incident-status";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { CitizenIncident } from "@/types/citizen-incident";
import type { IntakeLocation } from "@/types/intake";

function formatLocation(location: IntakeLocation | null | undefined) {
  if (!location) return null;

  return (
    location.address_text ||
    location.place_name ||
    "Map location selected"
  );
}

function getIncidentResolvedLabel(incident: CitizenIncident) {
  if (incident.resolved_at) {
    return `Resolved: ${formatBangladeshTime(incident.resolved_at)}`;
  }

  if (incident.closed_at) {
    return `Closed: ${formatBangladeshTime(incident.closed_at)}`;
  }

  return null;
}

export default function CitizenIncidentsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [incidents, setIncidents] = useState<CitizenIncident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const summary = useMemo(
    () => ({
      total: incidents.length,
      active: incidents.filter(isActiveIncident).length,
      final: incidents.filter(isFinalIncident).length,
      resolved: incidents.filter(isResolvedIncident).length,
    }),
    [incidents],
  );

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
        const data = await getMyIncidents();
        setIncidents(
          sortNewestFirst(data.incidents ?? [], (incident) => [
            incident.last_updated,
            incident.reported_at,
            incident.created_at,
          ]),
        );
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unexpected error while loading your incidents.",
        );
      } finally {
        setIsLoading(false);
      }
    };

    void loadIncidents();
  }, [isChecking]);

  if (isChecking) {
    return <PageLoading label="Loading incidents" />;
  }

  return (
    <DashboardLayout
      title="My Incidents"
      subtitle="Emergency incidents linked to your reports"
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
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#B71C1C] text-white">
                  <AlertTriangle className="h-5 w-5" aria-hidden />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Emergency Incident Summary
                  </h2>
                  <p className="mt-1 text-sm text-gray-600">
                    Incidents appear here when emergency responders link them to your intake reports.
                  </p>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm">
                <FileText className="h-5 w-5 text-[#002D62]" aria-hidden />
                <div className="mt-4 text-3xl font-bold text-[#002D62]">
                  {summary.total}
                </div>
                <p className="mt-1 text-sm font-semibold text-gray-900">
                  Total Incidents
                </p>
              </div>
              <div className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm">
                <AlertTriangle className="h-5 w-5 text-amber-700" aria-hidden />
                <div className="mt-4 text-3xl font-bold text-[#002D62]">
                  {summary.active}
                </div>
                <p className="mt-1 text-sm font-semibold text-gray-900">
                  Active Incidents
                </p>
              </div>
              <div className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm">
                <CheckCircle2 className="h-5 w-5 text-[#006747]" aria-hidden />
                <div className="mt-4 text-3xl font-bold text-[#002D62]">
                  {summary.resolved}
                </div>
                <p className="mt-1 text-sm font-semibold text-gray-900">
                  Resolved Incidents
                </p>
                <p className="mt-2 text-xs text-gray-600">
                  Final incidents: {summary.final}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <FileText className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Linked Emergency Incidents
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  Newest incident updates appear first.
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-sm text-gray-600">Loading your incidents...</p>
            ) : null}

            {error ? <ErrorAlert message={error} /> : null}

            {!isLoading && !error && incidents.length === 0 ? (
              <EmptyState
                title="No incidents yet"
                description="No emergency incidents linked to your reports yet."
                icon={<AlertTriangle className="h-6 w-6" aria-hidden />}
              />
            ) : null}

            {!isLoading && !error && incidents.length > 0 ? (
              <div className="grid gap-4">
                {incidents.map((incident) => {
                  const locationText =
                    formatLocation(incident.location) ||
                    incident.location_text ||
                    null;
                  const resolvedLabel = getIncidentResolvedLabel(incident);

                  return (
                    <article
                      id={incident.public_uuid}
                      key={incident.public_uuid}
                      className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm"
                    >
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0">
                          <p className="text-xs font-bold uppercase tracking-wide text-[#B71C1C]">
                            {incident.incident_code}
                          </p>
                          <h3 className="mt-1 break-words text-lg font-semibold text-gray-900">
                            {incident.title || "Emergency incident"}
                          </h3>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge tone={incident.status_code}>
                            {formatIncidentStatus(incident.status_code)}
                          </Badge>
                          <Badge tone={incident.severity_code}>
                            {formatBadgeLabel(incident.severity_code)}
                          </Badge>
                        </div>
                      </div>

                      {incident.description ? (
                        <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                          {incident.description}
                        </p>
                      ) : null}

                      <div className="mt-4 grid gap-3 text-sm text-gray-600 sm:grid-cols-2">
                        <p>
                          <span className="font-medium text-gray-800">
                            Category:
                          </span>{" "}
                          {formatBadgeLabel(incident.category_code)}
                        </p>
                        <p>
                          <span className="font-medium text-gray-800">
                            Origin:
                          </span>{" "}
                          {formatBadgeLabel(incident.origin_type)}
                        </p>
                        <p>
                          <span className="font-medium text-gray-800">
                            Linked Report:
                          </span>{" "}
                          {incident.intake_report_code}
                        </p>
                        <p>
                          <span className="font-medium text-gray-800">
                            Reported:
                          </span>{" "}
                          {formatBangladeshTime(incident.reported_at)}
                        </p>
                        {resolvedLabel ? (
                          <p>
                            <span className="font-medium text-gray-800">
                              {resolvedLabel}
                            </span>
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
                              {locationText ?? "-"}
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="mt-5">
                        <Button
                          type="button"
                          size="sm"
                          variant="secondary"
                          onClick={() =>
                            router.push(
                              `/dashboard/citizen/reports/${incident.intake_public_uuid}`,
                            )
                          }
                        >
                          View Linked Report
                          <ArrowRight className="h-4 w-4" aria-hidden />
                        </Button>
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
