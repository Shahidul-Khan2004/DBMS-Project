"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowRight } from "lucide-react";
import {
  CitizenLocationPill,
  CitizenMetaItem,
  CitizenRecordCard,
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
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
  isTerminalIncident,
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
    return formatBangladeshTime(incident.resolved_at);
  }

  if (incident.closed_at) {
    return formatBangladeshTime(incident.closed_at);
  }

  return null;
}

export default function CitizenIncidentsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [incidents, setIncidents] = useState<CitizenIncident[]>([]);
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
        const data = await getMyIncidents();
        setIncidents(
          sortNewestFirst(data.incidents ?? [], (incident) => [
            incident.last_updated,
            incident.reported_at,
            incident.created_at,
          ]),
        );
      } catch (err) {
        console.error("Failed to load citizen incidents", err);
        setError(
          getCitizenFriendlyError(
            err,
            "We could not load your linked incidents right now. Please try again.",
          ),
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
      <div className="space-y-3">
        <CitizenSectionCard
          title="Linked Emergency Incidents"
          subtitle="Newest incident updates appear first."
          icon={<AlertTriangle className="h-5 w-5" aria-hidden />}
          className="flex max-h-[calc(100dvh-11rem)] min-h-[22rem] flex-col"
          contentClassName="min-h-0 flex-1 overflow-y-auto overscroll-y-contain"
        >
            {isLoading ? (
              <p className="text-sm text-[#42547A]">Loading your incidents...</p>
            ) : null}

            {error ? <ErrorAlert message={error} /> : null}

            {!isLoading && !error && incidents.length === 0 ? (
              <EmptyState
                title="No incidents linked yet."
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
                  const isFinal = isTerminalIncident(incident.status_code);

                  return (
                    <CitizenRecordCard
                      id={incident.public_uuid}
                      key={incident.public_uuid}
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
                          {incident.severity_code ? (
                            <Badge tone={incident.severity_code}>
                              {formatBadgeLabel(incident.severity_code)}
                            </Badge>
                          ) : null}
                        </div>
                      </div>

                      {incident.description ? (
                        <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                          {incident.description}
                        </p>
                      ) : null}

                      <div className="mt-4 grid gap-3 sm:grid-cols-2">
                        <CitizenMetaItem
                          label="Category"
                          value={formatBadgeLabel(incident.category_code)}
                        />
                        <CitizenMetaItem
                          label="Origin"
                          value={formatBadgeLabel(incident.origin_type)}
                        />
                        <CitizenMetaItem
                          label="Linked Report"
                          value={incident.intake_report_code}
                        />
                        <CitizenMetaItem
                          label="Reported"
                          value={formatBangladeshTime(incident.reported_at)}
                        />
                        {resolvedLabel ? (
                          <CitizenMetaItem label="Resolved" value={resolvedLabel} />
                        ) : null}
                        <div className="sm:col-span-2">
                          <CitizenLocationPill>{locationText ?? "-"}</CitizenLocationPill>
                        </div>
                      </div>

                      <div className="mt-5 flex flex-wrap items-center gap-3">
                        <Button
                          type="button"
                          size="sm"
                          variant="secondary"
                          onClick={() =>
                            router.push(
                              `/dashboard/citizen/incidents/${incident.public_uuid}`,
                            )
                          }
                        >
                          View Details
                          <ArrowRight className="h-4 w-4" aria-hidden />
                        </Button>
                        {isFinal ? (
                          <span className="rounded-xl border border-[#002D62]/10 bg-[#EFF6FF] px-3 py-2 text-sm text-[#42547A]">
                            Final and view-only
                          </span>
                        ) : null}
                      </div>
                    </CitizenRecordCard>
                  );
                })}
              </div>
            ) : null}
        </CitizenSectionCard>
      </div>
    </DashboardLayout>
  );
}
