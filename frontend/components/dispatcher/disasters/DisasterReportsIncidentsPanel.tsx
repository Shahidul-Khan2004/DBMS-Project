"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ChevronRight } from "lucide-react";
import { toast } from "sonner";
import {
  getDisasterOutlineButtonClasses,
  getDisasterSegmentActiveClasses,
} from "@/components/dispatcher/disasters/disasterColors";
import { getDispatcherClickableInsetRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { getIntakeStatusLabel } from "@/components/dispatcher/triage/intakeStatus";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/StatusState";
import {
  listCandidateDisasterIncidents,
  listCandidateDisasterReports,
  type CandidateDisasterReport,
} from "@/lib/disaster-dispatcher-api";
import { submitLinkIncidentToDisaster } from "@/lib/disaster-link-submit";
import { formatBangladeshTime } from "@/lib/datetime";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import { formatIncidentStatus } from "@/lib/incident-status";
import { formatIntakeAgeLabel } from "@/lib/format-relative-age";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";
import { ApiError, getApiErrorMessage } from "@/lib/api";

type ReportsTab = "linked" | "reports" | "incidents";

const TAB_OPTIONS: { value: ReportsTab; label: string }[] = [
  { value: "linked", label: "Linked Incidents" },
  { value: "reports", label: "Candidate Reports" },
  { value: "incidents", label: "Candidate Incidents" },
];

function GreenActionButton({
  label,
  onClick,
  disabled,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`${getDisasterOutlineButtonClasses()} disabled:cursor-not-allowed disabled:opacity-50`}
    >
      {label}
    </button>
  );
}

export function DisasterReportsIncidentsPanel({
  dashboard,
  disasterPublicUuid,
  onAddReport,
  onLinkIncident,
  onRefresh,
  className = "min-h-0 flex-1",
}: {
  dashboard: OperationsDisasterDashboard;
  disasterPublicUuid: string;
  onAddReport: (preselectedReportPublicUuid?: string) => void;
  onLinkIncident: () => void;
  onRefresh: () => void | Promise<void>;
  className?: string;
}) {
  const [activeTab, setActiveTab] = useState<ReportsTab>("linked");
  const [candidateReports, setCandidateReports] = useState<CandidateDisasterReport[]>(
    [],
  );
  const [candidateIncidents, setCandidateIncidents] = useState<OperationsIncidentRow[]>(
    [],
  );
  const [loadingCandidates, setLoadingCandidates] = useState(false);
  const [linkingIncidentUuid, setLinkingIncidentUuid] = useState<string | null>(null);

  const linkedIncidents = dashboard.linked_incidents ?? [];

  const loadCandidates = useCallback(async () => {
    setLoadingCandidates(true);
    try {
      const [reportsResult, incidents] = await Promise.all([
        listCandidateDisasterReports(dashboard),
        listCandidateDisasterIncidents(dashboard),
      ]);
      setCandidateReports(reportsResult.allPending);
      setCandidateIncidents(incidents);
    } catch {
      setCandidateReports([]);
      setCandidateIncidents([]);
    } finally {
      setLoadingCandidates(false);
    }
  }, [dashboard]);

  useEffect(() => {
    if (activeTab === "reports" || activeTab === "incidents") {
      void loadCandidates();
    }
  }, [activeTab, loadCandidates]);

  const handleLinkCandidateIncident = async (incidentPublicUuid: string) => {
    setLinkingIncidentUuid(incidentPublicUuid);
    try {
      const result = await submitLinkIncidentToDisaster(
        disasterPublicUuid,
        incidentPublicUuid,
      );
      if (result.ok) {
        toast.success("Incident linked to disaster.");
        await onRefresh();
        void loadCandidates();
      } else {
        toast.error(result.message);
        if (result.status === 409) {
          await onRefresh();
        }
      }
    } catch (err) {
      toast.error(
        err instanceof ApiError
          ? getApiErrorMessage(err, "Failed to link incident.")
          : "Failed to link incident.",
      );
    } finally {
      setLinkingIncidentUuid(null);
    }
  };

  return (
    <section
      className={`flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-slate-200/90 bg-white shadow-sm ${className}`}
    >
      <div className="flex shrink-0 flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-4 py-3 sm:px-5">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-900">
            Reports &amp; Linked Incidents
          </h3>
          <p className="mt-0.5 text-xs text-slate-600">
            Add disaster-related reports and monitor linked emergency incidents.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <GreenActionButton label="+ Add Report" onClick={() => onAddReport()} />
          <GreenActionButton label="+ Link Existing Incident" onClick={onLinkIncident} />
        </div>
      </div>

      <div className="shrink-0 border-b border-slate-100 px-4 py-2 sm:px-5">
        <div
          role="tablist"
          aria-label="Reports and incidents views"
          className="inline-flex max-w-full flex-wrap gap-1 rounded-lg border border-slate-200 bg-slate-50/80 p-1"
        >
          {TAB_OPTIONS.map((option) => {
            const isActive = activeTab === option.value;
            return (
              <button
                key={option.value}
                type="button"
                role="tab"
                aria-selected={isActive}
                onClick={() => setActiveTab(option.value)}
                className={`inline-flex shrink-0 cursor-pointer items-center rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive
                    ? getDisasterSegmentActiveClasses()
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                }`}
              >
                {option.label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-4 py-3 sm:px-5">
          {activeTab === "linked" ? (
            linkedIncidents.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12">
                <EmptyState
                  title="No linked incidents yet"
                  description="Add a report or link an existing incident to begin disaster response tracking."
                />
              </div>
            ) : (
              <ul className="space-y-2">
                {linkedIncidents.map((incident) => {
                  const uuid = incident.incident_public_uuid;
                  if (!uuid) return null;
                  return (
                    <li key={uuid}>
                      <Link
                        href={`/dashboard/dispatcher/incidents/${encodeURIComponent(uuid)}`}
                        className={`group flex items-center justify-between gap-3 rounded-lg border px-3 py-2.5 ${getDispatcherClickableInsetRowClasses()}`}
                      >
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium text-slate-900">
                            {incident.title ?? "Untitled incident"}
                          </p>
                          <p className="mt-0.5 text-xs text-slate-600">
                            {incident.incident_code ?? "—"}
                            {incident.location_upazila_name
                              ? ` · ${incident.location_upazila_name}`
                              : ""}
                            {incident.linked_at
                              ? ` · Linked ${formatBangladeshTime(incident.linked_at)}`
                              : ""}
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          {incident.incident_status ? (
                            <Badge size="compact" tone={incident.incident_status}>
                              {formatBadgeLabel(
                                formatIncidentStatus(incident.incident_status),
                              )}
                            </Badge>
                          ) : null}
                          <span className="text-xs font-medium text-[#006747]">
                            Open Command →
                          </span>
                          <ChevronRight
                            className="h-4 w-4 text-[#006747] transition-transform group-hover:translate-x-0.5"
                            aria-hidden
                          />
                        </div>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )
          ) : null}

          {activeTab === "reports" ? (
            loadingCandidates ? (
              <p className="text-sm text-slate-600">Loading candidate reports…</p>
            ) : candidateReports.length === 0 ? (
              <p className="text-sm text-slate-600">No pending reports available.</p>
            ) : (
              <div className="space-y-4">
                {candidateReports.some((r) => r.affectedAreaMatch) ? (
                  <section>
                    <h4 className="text-xs font-semibold uppercase tracking-wide text-[#006747]">
                      Affected area matches
                    </h4>
                    <ul className="mt-2 space-y-2">
                      {candidateReports
                        .filter((report) => report.affectedAreaMatch)
                        .map((report) => (
                          <CandidateReportRow
                            key={report.public_uuid}
                            report={report}
                            onAdd={() => onAddReport(report.public_uuid)}
                          />
                        ))}
                    </ul>
                  </section>
                ) : null}
                <section>
                  <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    All pending reports
                  </h4>
                  <ul className="mt-2 space-y-2">
                    {candidateReports
                      .filter((report) => !report.affectedAreaMatch)
                      .map((report) => (
                        <CandidateReportRow
                          key={report.public_uuid}
                          report={report}
                          onAdd={() => onAddReport(report.public_uuid)}
                        />
                      ))}
                  </ul>
                </section>
              </div>
            )
          ) : null}

          {activeTab === "incidents" ? (
            loadingCandidates ? (
              <p className="text-sm text-slate-600">Loading candidate incidents…</p>
            ) : candidateIncidents.length === 0 ? (
              <p className="text-sm text-slate-600">
                No linkable incidents available for this disaster.
              </p>
            ) : (
              <ul className="space-y-2">
                {candidateIncidents.map((incident) => (
                  <li
                    key={incident.public_uuid}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-slate-900">
                        {incident.title?.trim() || "Untitled incident"}
                      </p>
                      <p className="mt-0.5 text-xs text-slate-600">
                        {incident.incident_code ?? "—"}
                        {incident.location?.place_name
                          ? ` · ${incident.location.place_name}`
                          : ""}
                      </p>
                      <div className="mt-1 flex flex-wrap gap-2">
                        <Badge size="compact" tone={incident.status_code}>
                          {formatBadgeLabel(formatIncidentStatus(incident.status_code))}
                        </Badge>
                        {incident.severity_code ? (
                          <Badge size="compact" tone="warning">
                            {formatBadgeLabel(incident.severity_code)}
                          </Badge>
                        ) : null}
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={linkingIncidentUuid === incident.public_uuid}
                      onClick={() =>
                        void handleLinkCandidateIncident(incident.public_uuid)
                      }
                      className={`${getDisasterOutlineButtonClasses()} disabled:cursor-not-allowed disabled:opacity-50`}
                    >
                      {linkingIncidentUuid === incident.public_uuid
                        ? "Linking…"
                        : "Link to Disaster"}
                    </button>
                  </li>
                ))}
              </ul>
            )
          ) : null}
        </div>
      </div>
    </section>
  );
}

function CandidateReportRow({
  report,
  onAdd,
}: {
  report: CandidateDisasterReport;
  onAdd: () => void;
}) {
  const locationPreview =
    report.location?.address_text?.trim() ||
    report.location?.place_name?.trim() ||
    null;

  return (
    <li className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5">
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-slate-900">
          {report.summary?.trim() || "Untitled report"}
        </p>
        <p className="mt-0.5 font-mono text-xs text-slate-500">{report.report_code}</p>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-600">
          <span>{formatBadgeLabel(report.category_code)}</span>
          <Badge size="compact" tone="neutral">
            {getIntakeStatusLabel(report.intake_status as "received" | "under_review")}
          </Badge>
          <span>
            Reported{" "}
            {formatIntakeAgeLabel(
              report.intake_status,
              report.reported_at,
              report.updated_at,
            )}
          </span>
        </div>
        {locationPreview ? (
          <p className="mt-0.5 text-xs text-slate-500">{locationPreview}</p>
        ) : null}
      </div>
      <button
        type="button"
        onClick={onAdd}
        className={getDisasterOutlineButtonClasses()}
      >
        Add to Disaster
      </button>
    </li>
  );
}
