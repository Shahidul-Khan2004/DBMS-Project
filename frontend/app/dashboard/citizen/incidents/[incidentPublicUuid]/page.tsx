"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AlertTriangle, FileText } from "lucide-react";
import {
  CitizenBackButton,
  CitizenLocationPill,
  CitizenMetaItem,
  CitizenPageContent,
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { clearAuthSession } from "@/lib/auth-store";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { formatBangladeshTime } from "@/lib/datetime";
import { apiGet } from "@/lib/api";
import {
  formatIncidentCategory,
  formatIncidentStatus,
  isTerminalIncident,
} from "@/lib/incident-status";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { CitizenIncident } from "@/types/citizen-incident";
import type { IntakeLocation, IntakeReportListResponse } from "@/types/intake";

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

function getWhatHappensNext(statusCode: string) {
  if (isTerminalIncident(statusCode)) {
    return "This emergency response is complete. No further action is needed from you.";
  }

  if (statusCode === "in_progress" || statusCode === "dispatched") {
    return "Responders are actively working on this emergency. Check back here for status updates.";
  }

  return "Your report is being reviewed and coordinated. Updates will appear here as the response progresses.";
}

export default function CitizenIncidentDetailPage() {
  const router = useRouter();
  const params = useParams();
  const incidentPublicUuid = params.incidentPublicUuid as string;
  const isChecking = useAuthGuard(["citizen"]);
  const [incident, setIncident] = useState<CitizenIncident | null>(null);
  const [linkedReportSummary, setLinkedReportSummary] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadIncident = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [incidentsResult, reportsResult] = await Promise.allSettled([
        getMyIncidents(),
        apiGet<IntakeReportListResponse>("/intake/reports/my"),
      ]);

      if (incidentsResult.status === "rejected") {
        throw incidentsResult.reason;
      }

      const found =
        incidentsResult.value.incidents?.find(
          (item) => item.public_uuid === incidentPublicUuid,
        ) ?? null;
      setIncident(found);

      if (reportsResult.status === "fulfilled" && found) {
        const linkedReport = reportsResult.value.reports?.find(
          (report) => report.public_uuid === found.intake_public_uuid,
        );
        setLinkedReportSummary(linkedReport?.summary ?? null);
      } else {
        setLinkedReportSummary(null);
      }
    } catch (err) {
      console.error("Failed to load citizen incident details", err);
      setError(
        getCitizenFriendlyError(
          err,
          "We could not load this emergency response right now. Please try again.",
        ),
      );
      setIncident(null);
      setLinkedReportSummary(null);
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
    return <PageLoading label="Loading emergency response" />;
  }

  const isFinal = incident ? isTerminalIncident(incident.status_code) : false;
  const finalTime = incident ? getFinalTimeLabel(incident) : null;
  const locationText =
    formatLocation(incident?.location) ||
    incident?.location_text ||
    null;

  return (
    <DashboardLayout
      title="Emergency Response Details"
      subtitle="Status and information for your linked emergency response."
      onLogout={handleLogout}
    >
      <CitizenPageContent>
        <CitizenBackButton
          href="/dashboard/citizen/incidents"
          label="Back to Emergency Responses"
        />

        {error ? <ErrorAlert message={error} /> : null}

        {isLoading ? (
          <p className="text-sm text-[#42547A]">Loading emergency response...</p>
        ) : !incident ? (
          <EmptyState
            title="Emergency response not found"
            description="This emergency response is not available to your account."
            icon={<AlertTriangle className="h-6 w-6" aria-hidden />}
          />
        ) : (
          <div className="grid gap-6 lg:grid-cols-2">
            <CitizenSectionCard
              title="Emergency Response Status"
              icon={<AlertTriangle className="h-5 w-5" aria-hidden />}
            >
              <div className="space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h2 className="break-words text-xl font-semibold text-slate-950">
                      {incident.title || "Emergency response"}
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

                {incident.description ? (
                  <p className="whitespace-pre-wrap text-sm leading-6 text-[#42547A]">
                    {incident.description}
                  </p>
                ) : null}

                <div className="grid gap-3 sm:grid-cols-2">
                  <CitizenMetaItem
                    label="Response status"
                    value={formatIncidentStatus(incident.status_code)}
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
                  {finalTime ? (
                    <CitizenMetaItem
                      label={finalTime.label}
                      value={finalTime.value}
                    />
                  ) : null}
                </div>

                {isFinal ? (
                  <p className="rounded-xl border border-slate-200/80 bg-[#F6F9FE] px-4 py-3 text-sm text-[#42547A]">
                    This emergency response is complete and view-only.
                  </p>
                ) : null}
              </div>
            </CitizenSectionCard>

            <CitizenSectionCard
              title="Current Status"
              subtitle="What happens next"
            >
              <p className="text-sm leading-6 text-[#42547A]">
                {getWhatHappensNext(incident.status_code)}
              </p>
            </CitizenSectionCard>

            <CitizenSectionCard
              title="Original Report Summary"
              icon={<FileText className="h-5 w-5" aria-hidden />}
            >
              <p className="text-sm leading-6 text-slate-900">
                {linkedReportSummary || "Your submitted report summary is not available."}
              </p>
              <p className="mt-3 text-xs text-[#60739A]">
                This is the report you submitted that was connected to this emergency
                response.
              </p>
            </CitizenSectionCard>

            <CitizenSectionCard title="Location">
              <CitizenLocationPill>{locationText ?? "-"}</CitizenLocationPill>
            </CitizenSectionCard>
          </div>
        )}
      </CitizenPageContent>
    </DashboardLayout>
  );
}
