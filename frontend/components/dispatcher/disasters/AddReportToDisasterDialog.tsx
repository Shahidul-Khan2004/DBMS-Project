"use client";

import Link from "next/link";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import { createPortal } from "react-dom";
import { toast } from "sonner";
import { getDisasterOutlineButtonClasses } from "@/components/dispatcher/disasters/disasterColors";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { getIntakeStatusLabel } from "@/components/dispatcher/triage/intakeStatus";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import {
  linkIntakeReportToIncident,
  listCandidateDisasterReports,
  promoteIntakeReportToEmergency,
  type CandidateDisasterReport,
} from "@/lib/disaster-dispatcher-api";
import { submitLinkIncidentToDisaster } from "@/lib/disaster-link-submit";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import {
  getOperationsIncidents,
  LINKABLE_INCIDENT_STATUSES,
  TERMINAL_INCIDENT_STATUSES,
  type OperationsIncidentRow,
} from "@/lib/operations-intake-triage";
import { formatIntakeAgeLabel } from "@/lib/format-relative-age";
import type { OperationsIntakeReport } from "@/types/operations-intake";
import type { LinkIntakeToIncidentPayload } from "@/lib/operations-intake-triage";

const LINK_NOTE_MAX_LENGTH = 500;

type AddPath = "new_incident" | "existing_incident";

type AddReportToDisasterDialogProps = {
  open: boolean;
  disasterPublicUuid: string;
  dashboard: OperationsDisasterDashboard;
  preselectedReportPublicUuid?: string | null;
  onClose: () => void;
  onSuccess?: () => void | Promise<void>;
};

function matchesReportSearch(report: OperationsIntakeReport, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  const loc = report.location;
  const locationText =
    loc?.address_text?.trim() || loc?.place_name?.trim() || "";
  const haystack = [report.report_code, report.summary, report.category_code, locationText]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(normalized);
}

function ReportSummary({ report }: { report: OperationsIntakeReport }) {
  const locationPreview =
    report.location?.address_text?.trim() ||
    report.location?.place_name?.trim() ||
    null;

  return (
    <div className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5">
      <p className="text-sm font-semibold text-slate-900">
        {report.summary?.trim() || "Untitled report"}
      </p>
      <p className="mt-0.5 font-mono text-xs text-slate-500">{report.report_code}</p>
      <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-600">
        <span>{formatBadgeLabel(report.category_code)}</span>
        <span className="text-slate-300" aria-hidden>
          ·
        </span>
        <span>
          {getIntakeStatusLabel(report.intake_status as "received" | "under_review")}
        </span>
        {locationPreview ? (
          <>
            <span className="text-slate-300" aria-hidden>
              ·
            </span>
            <span>{locationPreview}</span>
          </>
        ) : null}
      </div>
    </div>
  );
}

export function AddReportToDisasterDialog({
  open,
  disasterPublicUuid,
  dashboard,
  preselectedReportPublicUuid,
  onClose,
  onSuccess,
}: AddReportToDisasterDialogProps) {
  const [step, setStep] = useState<1 | 2>(1);
  const [reports, setReports] = useState<CandidateDisasterReport[]>([]);
  const [incidents, setIncidents] = useState<OperationsIncidentRow[]>([]);
  const [selectedReport, setSelectedReport] = useState<OperationsIntakeReport | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [addPath, setAddPath] = useState<AddPath>("new_incident");
  const [severityCode, setSeverityCode] = useState<
    "low" | "medium" | "high" | "critical"
  >("medium");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [existingIncidentUuid, setExistingIncidentUuid] = useState("");
  const [linkType, setLinkType] =
    useState<LinkIntakeToIncidentPayload["linkType"]>("supporting_report");
  const [linkNote, setLinkNote] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successIncidentUuid, setSuccessIncidentUuid] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setIsLoading(true);
    setLoadError(null);
    try {
      const result = await listCandidateDisasterReports(dashboard);
      setReports(result.allPending);
    } catch {
      setLoadError("Unable to load intake reports.");
      setReports([]);
    } finally {
      setIsLoading(false);
    }
  }, [dashboard]);

  const loadIncidents = useCallback(async () => {
    try {
      const data = await getOperationsIncidents({ limit: 100, offset: 0 });
      setIncidents(
        (data.incidents ?? []).filter(
          (incident) => !TERMINAL_INCIDENT_STATUSES.has(incident.status_code),
        ),
      );
    } catch {
      setIncidents([]);
    }
  }, []);

  const resetState = useCallback(() => {
    setStep(1);
    setSelectedReport(null);
    setSearchQuery("");
    setAddPath("new_incident");
    setSeverityCode("medium");
    setIncidentTitle("");
    setIncidentDescription("");
    setExistingIncidentUuid("");
    setLinkType("supporting_report");
    setLinkNote("");
    setLoadError(null);
    setSubmitError(null);
    setSuccessIncidentUuid(null);
  }, []);

  useEffect(() => {
    if (!open) return;
    resetState();
    void loadReports();
    void loadIncidents();
  }, [open, loadReports, loadIncidents, resetState]);

  useEffect(() => {
    if (!open || !preselectedReportPublicUuid || reports.length === 0) return;
    const match = reports.find((r) => r.public_uuid === preselectedReportPublicUuid);
    if (match) {
      setSelectedReport(match);
      setIncidentTitle(match.summary?.trim() ?? "");
      setStep(2);
    }
  }, [open, preselectedReportPublicUuid, reports]);

  const filteredReports = useMemo(
    () => reports.filter((report) => matchesReportSearch(report, searchQuery)),
    [reports, searchQuery],
  );

  const handleSelectReport = (report: OperationsIntakeReport) => {
    setSelectedReport(report);
    setIncidentTitle(report.summary?.trim() ?? "");
    setSubmitError(null);
    setStep(2);
  };

  const handleDisasterLink = async (incidentUuid: string): Promise<boolean> => {
    const linkResult = await submitLinkIncidentToDisaster(
      disasterPublicUuid,
      incidentUuid,
    );
    if (linkResult.ok) return true;
    if (linkResult.status === 409) {
      toast.warning(linkResult.message);
      await onSuccess?.();
      return false;
    }
    toast.warning(
      "Report was routed to an incident, but disaster linking failed. You can attach the incident from Incident Command.",
    );
    setSuccessIncidentUuid(incidentUuid);
    return false;
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedReport) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      let incidentUuid: string;

      if (addPath === "new_incident") {
        const data = await promoteIntakeReportToEmergency(selectedReport.public_uuid, {
          severityCode,
          incidentTitle: incidentTitle.trim() || undefined,
          incidentDescription: incidentDescription.trim() || undefined,
        });
        incidentUuid = data.incident?.public_uuid ?? "";
        if (!incidentUuid) {
          setSubmitError(
            "Emergency incident was created but the response was incomplete.",
          );
          setIsSubmitting(false);
          return;
        }
      } else {
        if (!existingIncidentUuid) {
          setSubmitError("Select an existing emergency incident.");
          setIsSubmitting(false);
          return;
        }
        await linkIntakeReportToIncident(existingIncidentUuid, {
          intakeReportPublicUuid: selectedReport.public_uuid,
          linkType,
          note: linkNote.trim() || undefined,
        });
        incidentUuid = existingIncidentUuid;
      }

      const linked = await handleDisasterLink(incidentUuid);
      setSuccessIncidentUuid(incidentUuid);

      if (linked) {
        toast.success(
          addPath === "new_incident"
            ? "Report promoted and incident linked to disaster."
            : "Report linked through existing incident.",
        );
        await onSuccess?.();
        onClose();
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setSubmitError(getApiErrorMessage(err, "Unable to add report to disaster."));
      } else {
        setSubmitError("Unable to add report to disaster.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  const dialog = (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4 py-6">
      <form
        onSubmit={(event) => void handleSubmit(event)}
        className="flex max-h-[min(90vh,720px)] w-full max-w-2xl flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="add-report-disaster-title"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2 id="add-report-disaster-title" className="text-lg font-semibold text-slate-900">
            Add Report to Disaster
          </h2>
          <p className="mt-0.5 text-xs text-slate-600">
            Route an intake report through an emergency incident, then link to this disaster.
          </p>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {step === 1 ? (
            <div className="space-y-3">
              <FieldLabel required>Select intake report</FieldLabel>
              <input
                type="search"
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                placeholder="Search reports"
                className={triageFieldClassName}
                disabled={isSubmitting || isLoading}
              />
              {isLoading ? (
                <p className="text-sm text-slate-600">Loading reports…</p>
              ) : loadError ? (
                <ErrorAlert message={loadError} />
              ) : filteredReports.length === 0 ? (
                <p className="text-sm text-slate-600">No pending reports available.</p>
              ) : (
                <ul className="max-h-80 space-y-2 overflow-y-auto pr-1">
                  {filteredReports.map((report) => (
                    <li key={report.public_uuid}>
                      <button
                        type="button"
                        disabled={isSubmitting}
                        onClick={() => handleSelectReport(report)}
                        className={`w-full rounded-lg border px-3 py-2.5 text-left ${getDispatcherSelectableRowClasses({
                          selected: selectedReport?.public_uuid === report.public_uuid,
                          disabled: isSubmitting,
                          variant: "flat",
                        })}`}
                      >
                        <p className="text-sm font-semibold text-slate-900">
                          {report.summary?.trim() || "Untitled report"}
                        </p>
                        <p className="mt-0.5 font-mono text-xs text-slate-500">
                          {report.report_code}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">
                          Reported{" "}
                          {formatIntakeAgeLabel(
                            report.intake_status,
                            report.reported_at,
                            report.updated_at,
                          )}
                          {report.affectedAreaMatch ? " · Affected area match" : ""}
                        </p>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : selectedReport ? (
            <div className="space-y-4">
              <ReportSummary report={selectedReport} />

              <fieldset className="space-y-2">
                <legend className="text-sm font-medium text-slate-900">
                  How should this report be added?
                </legend>
                <label className="flex cursor-pointer items-start gap-2 text-sm text-slate-700">
                  <input
                    type="radio"
                    name="add-path"
                    checked={addPath === "new_incident"}
                    onChange={() => setAddPath("new_incident")}
                    disabled={isSubmitting}
                    className="mt-0.5 text-[#006747] focus:ring-[#006747]/30"
                  />
                  <span>Create new emergency incident from this report</span>
                </label>
                <label className="flex cursor-pointer items-start gap-2 text-sm text-slate-700">
                  <input
                    type="radio"
                    name="add-path"
                    checked={addPath === "existing_incident"}
                    onChange={() => setAddPath("existing_incident")}
                    disabled={isSubmitting}
                    className="mt-0.5 text-[#006747] focus:ring-[#006747]/30"
                  />
                  <span>
                    Link report to an existing emergency incident, then attach to disaster
                  </span>
                </label>
              </fieldset>

              {addPath === "new_incident" ? (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <FieldLabel htmlFor="add-severity" required>
                      Severity
                    </FieldLabel>
                    <select
                      id="add-severity"
                      value={severityCode}
                      required
                      onChange={(event) =>
                        setSeverityCode(
                          event.target.value as "low" | "medium" | "high" | "critical",
                        )
                      }
                      className={triageFieldClassName}
                      disabled={isSubmitting}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                  <div>
                    <FieldLabel htmlFor="add-incident-title">Incident title</FieldLabel>
                    <input
                      id="add-incident-title"
                      value={incidentTitle}
                      onChange={(event) => setIncidentTitle(event.target.value)}
                      className={triageFieldClassName}
                      disabled={isSubmitting}
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <FieldLabel htmlFor="add-incident-description">
                      Incident description
                    </FieldLabel>
                    <textarea
                      id="add-incident-description"
                      value={incidentDescription}
                      onChange={(event) => setIncidentDescription(event.target.value)}
                      rows={2}
                      className={triageFieldClassName}
                      disabled={isSubmitting}
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <div>
                    <FieldLabel htmlFor="add-existing-incident" required>
                      Existing incident
                    </FieldLabel>
                    <select
                      id="add-existing-incident"
                      value={existingIncidentUuid}
                      onChange={(event) => setExistingIncidentUuid(event.target.value)}
                      className={triageFieldClassName}
                      disabled={isSubmitting}
                    >
                      <option value="">Select incident</option>
                      {incidents.map((incident) => (
                        <option key={incident.public_uuid} value={incident.public_uuid}>
                          {incident.incident_code ?? incident.public_uuid.slice(0, 8)} —{" "}
                          {incident.title}
                          {LINKABLE_INCIDENT_STATUSES.has(incident.status_code)
                            ? ""
                            : ` (${incident.status_code})`}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <FieldLabel htmlFor="add-link-type">Link type</FieldLabel>
                    <select
                      id="add-link-type"
                      value={linkType}
                      onChange={(event) =>
                        setLinkType(event.target.value as LinkIntakeToIncidentPayload["linkType"])
                      }
                      className={triageFieldClassName}
                      disabled={isSubmitting}
                    >
                      <option value="supporting_report">Supporting report</option>
                      <option value="follow_up_report">Follow-up report</option>
                    </select>
                  </div>
                  <div>
                    <FieldLabel htmlFor="add-link-note">Note</FieldLabel>
                    <textarea
                      id="add-link-note"
                      value={linkNote}
                      onChange={(event) => setLinkNote(event.target.value)}
                      rows={2}
                      maxLength={LINK_NOTE_MAX_LENGTH}
                      className={triageFieldClassName}
                      disabled={isSubmitting}
                    />
                    <p className="mt-1 text-xs text-slate-500">
                      {linkNote.length}/{LINK_NOTE_MAX_LENGTH}
                    </p>
                  </div>
                </div>
              )}

              {submitError ? <ErrorAlert message={submitError} /> : null}

              {successIncidentUuid && !isSubmitting ? (
                <p className="text-sm text-slate-700">
                  <Link
                    href={`/dashboard/dispatcher/incidents/${encodeURIComponent(successIncidentUuid)}`}
                    className="font-medium text-[#006747] hover:text-[#00543A]"
                  >
                    Open Incident Command →
                  </Link>
                </p>
              ) : null}
            </div>
          ) : null}
        </div>

        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={isSubmitting}
            onClick={() => {
              if (step === 2 && !preselectedReportPublicUuid) {
                setStep(1);
                setSubmitError(null);
              } else {
                onClose();
              }
            }}
          >
            {step === 2 && !preselectedReportPublicUuid ? "Back" : "Cancel"}
          </Button>
          {step === 2 ? (
            <button
              type="submit"
              disabled={isSubmitting || !selectedReport}
              className={`${getDisasterOutlineButtonClasses()} disabled:cursor-not-allowed disabled:opacity-50`}
            >
              {isSubmitting ? "Adding…" : "Add to Disaster"}
            </button>
          ) : null}
        </div>
      </form>
    </div>
  );

  if (typeof document === "undefined") return null;
  return createPortal(dialog, document.body);
}
