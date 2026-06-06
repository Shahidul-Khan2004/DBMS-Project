"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AlertTriangle, FileText } from "lucide-react";
import {
  CitizenBackButton,
  CitizenLocationPill,
  CitizenMetaItem,
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { clearAuthSession } from "@/lib/auth-store";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { formatBangladeshTime } from "@/lib/datetime";
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

function getFinalTimeLabel(incident: CitizenIncident) {
  if (incident.resolved_at) {
    return { label: "Resolved", value: formatBangladeshTime(incident.resolved_at) };
  }

  if (incident.closed_at) {
    return { label: "Closed", value: formatBangladeshTime(incident.closed_at) };
  }

  return null;
}

export default function CitizenIncidentDetailPage() {
  const router = useRouter();
  const params = useParams();
  const incidentPublicUuid = params.incidentPublicUuid as string;
  const isChecking = useAuthGuard(["citizen"]);
  const [incident, setIncident] = useState<CitizenIncident | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadIncident = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await getMyIncidents();
      setIncident(
        data.incidents?.find(
          (item) => item.public_uuid === incidentPublicUuid,
        ) ?? null,
      );
    } catch (err) {
      console.error("Failed to load citizen incident details", err);
      setError(
        getCitizenFriendlyError(
          err,
          "We could not load this incident right now. Please try again.",
        ),
      );
      setIncident(null);
    } finally {
      setIsLoading(false);
    }
  }, [incidentPublicUuid]);

  useEffect(() => {
    if (isChecking) return;
    void loadIncident();
  }, [isChecking, loadIncident]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading incident details" />;
  }

  const isFinal = incident ? isTerminalIncident(incident.status_code) : false;
  const finalTime = incident ? getFinalTimeLabel(incident) : null;
  const locationText =
    formatLocation(incident?.location) ||
    incident?.location_text ||
    null;

  return (
    <DashboardLayout
      title="Incident Details"
      subtitle={`Incident ${incident?.incident_code ?? ""}`.trim()}
      onLogout={handleLogout}
    >
      <div className="space-y-3">
        <div className="flex justify-start">
          <CitizenBackButton
            href="/dashboard/citizen/incidents"
            label="Back to My Incidents"
          />
        </div>

        {error ? <ErrorAlert message={error} /> : null}

        <CitizenSectionCard
          title="Incident Snapshot"
          subtitle="View the incident information linked to your report."
          icon={<AlertTriangle className="h-5 w-5" aria-hidden />}
        >
          {isLoading ? (
            <p className="text-sm text-[#42547A]">Loading incident details...</p>
          ) : !incident ? (
            <EmptyState
              title="Incident not found"
              description="This incident is not available to your account."
              icon={<AlertTriangle className="h-6 w-6" aria-hidden />}
            />
          ) : (
            <div className="space-y-5">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <p className="text-xs font-bold uppercase tracking-wide text-[#B71C1C]">
                    {incident.incident_code}
                  </p>
                  <h2 className="mt-1 break-words text-xl font-semibold text-gray-900">
                    {incident.title || "Emergency incident"}
                  </h2>
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

              {isFinal ? (
                <div className="rounded-xl border border-[#002D62]/10 bg-[#EFF6FF] px-4 py-3 text-sm text-[#42547A]">
                  This incident is final and view-only. No location, report, or
                  incident update actions are available.
                </div>
              ) : null}

              {incident.description ? (
                <p className="whitespace-pre-wrap text-sm leading-6 text-gray-700">
                  {incident.description}
                </p>
              ) : null}

              <div className="grid gap-3 sm:grid-cols-2">
                <CitizenMetaItem
                  label="Status"
                  value={formatIncidentStatus(incident.status_code)}
                />
                <CitizenMetaItem
                  label="Severity"
                  value={formatBadgeLabel(incident.severity_code)}
                />
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
                <CitizenMetaItem
                  label="Last Updated"
                  value={formatBangladeshTime(incident.last_updated)}
                />
                {finalTime ? (
                  <CitizenMetaItem
                    label={finalTime.label}
                    value={finalTime.value}
                  />
                ) : null}
                <div className="sm:col-span-2">
                  <CitizenLocationPill>{locationText ?? "-"}</CitizenLocationPill>
                </div>
              </div>

              <div className="flex flex-wrap gap-3">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() =>
                    router.push(
                      `/dashboard/citizen/reports/${incident.intake_public_uuid}`,
                    )
                  }
                >
                  <FileText className="h-4 w-4" aria-hidden />
                  View Linked Report
                </Button>
              </div>
            </div>
          )}
        </CitizenSectionCard>
      </div>
    </DashboardLayout>
  );
}
