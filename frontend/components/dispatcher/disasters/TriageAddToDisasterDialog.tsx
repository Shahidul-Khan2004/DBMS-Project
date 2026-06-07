"use client";

import Link from "next/link";
import {
  useCallback,
  useEffect,
  useState,
  type FormEvent,
} from "react";
import { createPortal } from "react-dom";
import { toast } from "sonner";
import { getDisasterOutlineButtonClasses } from "@/components/dispatcher/disasters/disasterColors";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { IntakeStatusBadge } from "@/components/dispatcher/triage/IntakeStatusBadge";
import { hasValidReportedLocation } from "@/components/dispatcher/triage/reportedLocationCoords";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import {
  getOperationsDisaster,
  linkIntakeReportToIncident,
  listOperationsIncidents,
  promoteIntakeReportToEmergency,
  sortIncidentsForDisasterLink,
  type LinkIntakeToIncidentPayload,
} from "@/lib/disaster-dispatcher-api";
import { submitLinkIncidentToDisaster } from "@/lib/disaster-link-submit";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterSummary } from "@/lib/disaster-operations-types";
import {
  LINKABLE_INCIDENT_STATUSES,
  mapApiErrorToRouteMessage,
  TERMINAL_INCIDENT_STATUSES,
  type OperationsIncidentRow,
} from "@/lib/operations-intake-triage";
import { formatIncidentStatus } from "@/lib/incident-status";

const LINK_NOTE_MAX_LENGTH = 500;

type AddPath = "new_incident" | "existing_incident";

type TriageAddToDisasterDialogProps = {
  open: boolean;
  item: IntakeQueueItem | null;
  activeDisasters: OperationsDisasterSummary[];
  onClose: () => void;
  onSuccess?: () => void | Promise<void>;
  onEditLocation?: () => void;
};

function formatLocationPreview(item: IntakeQueueItem): string | null {
  const parts = [
    item.location.addressText?.trim(),
    item.location.areaName?.trim(),
    item.location.districtName?.trim(),
  ].filter(Boolean);
  if (parts.length === 0) return null;
  return parts.join(" · ");
}

function ReportSummarySection({ item }: { item: IntakeQueueItem }) {
  const locationPreview = formatLocationPreview(item);

  return (
    <section className="space-y-2">
      <h3 className="text-sm font-semibold text-slate-900">Selected Report Summary</h3>
      <div className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5">
        <p className="text-sm font-semibold text-slate-900">{item.summary}</p>
        <p className="mt-0.5 font-mono text-xs text-slate-500">{item.reportCode}</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <Badge size="compact" tone="neutral">
            {item.category}
          </Badge>
          <IntakeStatusBadge status={item.status} />
          {locationPreview ? (
            <span className="text-xs text-slate-600">{locationPreview}</span>
          ) : null}
        </div>
        <p className="mt-1 text-xs text-slate-500">Reported {item.ageLabel}</p>
      </div>
    </section>
  );
}

function DisasterSelectionSection({
  disasters,
  selectedDisasterUuid,
  onSelect,
  disabled,
}: {
  disasters: OperationsDisasterSummary[];
  selectedDisasterUuid: string;
  onSelect: (uuid: string) => void;
  disabled: boolean;
}) {
  if (disasters.length === 1) {
    const disaster = disasters[0];
    return (
      <section className="space-y-2">
        <FieldLabel required>Disaster</FieldLabel>
        <div className="rounded-lg border border-[#006747]/20 bg-[#F0F7F4]/60 px-3 py-2.5">
          <p className="text-sm font-semibold text-slate-900">{disaster.title}</p>
          <p className="mt-0.5 text-xs text-slate-600">{disaster.event_code}</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            <Badge size="compact" tone="active">
              {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
            </Badge>
            {disaster.severity_level ? (
              <Badge size="compact" tone="warning">
                {formatBadgeLabel(
                  formatDisasterSeverityLabel(disaster.severity_level),
                )}
              </Badge>
            ) : null}
            <Badge size="compact" tone="neutral">
              {formatBadgeLabel(
                formatDisasterEventTypeLabel(
                  disaster.event_type_code,
                  disaster.event_type_name,
                ),
              )}
            </Badge>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="space-y-2">
      <FieldLabel required>Disaster</FieldLabel>
      <ul className="max-h-48 space-y-2 overflow-y-auto pr-1">
        {disasters.map((disaster) => {
          const selected = selectedDisasterUuid === disaster.public_uuid;
          return (
            <li key={disaster.public_uuid}>
              <button
                type="button"
                disabled={disabled}
                onClick={() => onSelect(disaster.public_uuid)}
                className={`w-full rounded-lg border px-3 py-2.5 text-left ${getDispatcherSelectableRowClasses({
                  selected,
                  disabled,
                  variant: "flat",
                })}`}
              >
                <p className="text-sm font-semibold text-slate-900">{disaster.title}</p>
                <p className="mt-0.5 text-xs text-slate-600">{disaster.event_code}</p>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  <Badge size="compact" tone="active">
                    {formatBadgeLabel(
                      formatDisasterStatusLabel(disaster.status_code),
                    )}
                  </Badge>
                  {disaster.severity_level ? (
                    <Badge size="compact" tone="warning">
                      {formatBadgeLabel(
                        formatDisasterSeverityLabel(disaster.severity_level),
                      )}
                    </Badge>
                  ) : null}
                  <Badge size="compact" tone="neutral">
                    {formatBadgeLabel(
                      formatDisasterEventTypeLabel(
                        disaster.event_type_code,
                        disaster.event_type_name,
                      ),
                    )}
                  </Badge>
                </div>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function TriageAddToDisasterDialog({
  open,
  item,
  activeDisasters,
  onClose,
  onSuccess,
  onEditLocation,
}: TriageAddToDisasterDialogProps) {
  const [selectedDisasterUuid, setSelectedDisasterUuid] = useState("");
  const [addPath, setAddPath] = useState<AddPath>("new_incident");
  const [severityCode, setSeverityCode] = useState<
    "low" | "medium" | "high" | "critical"
  >("high");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [existingIncidentUuid, setExistingIncidentUuid] = useState("");
  const [linkType, setLinkType] =
    useState<LinkIntakeToIncidentPayload["linkType"]>("supporting_report");
  const [linkNote, setLinkNote] = useState("");
  const [incidents, setIncidents] = useState<OperationsIncidentRow[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successIncidentUuid, setSuccessIncidentUuid] = useState<string | null>(
    null,
  );

  const locationMissing = item ? !hasValidReportedLocation(item.location) : false;

  const resetState = useCallback(() => {
    setAddPath("new_incident");
    setSeverityCode("high");
    setIncidentTitle("");
    setIncidentDescription("");
    setExistingIncidentUuid("");
    setLinkType("supporting_report");
    setLinkNote("");
    setIncidents([]);
    setSubmitError(null);
    setSuccessIncidentUuid(null);
    if (activeDisasters.length === 1) {
      setSelectedDisasterUuid(activeDisasters[0].public_uuid);
    } else {
      setSelectedDisasterUuid("");
    }
  }, [activeDisasters]);

  useEffect(() => {
    if (!open) return;
    resetState();
    if (item) {
      setIncidentTitle(item.summary);
    }
  }, [open, item, resetState]);

  const loadIncidents = useCallback(async (disasterUuid: string) => {
    setIncidentsLoading(true);
    try {
      const [allIncidents, dashboard] = await Promise.all([
        listOperationsIncidents(),
        getOperationsDisaster(disasterUuid),
      ]);

      const linkedUuids = new Set(
        (dashboard.linked_incidents ?? [])
          .map((entry) => entry.incident_public_uuid)
          .filter(Boolean),
      );

      const filtered = allIncidents.filter(
        (incident) => !TERMINAL_INCIDENT_STATUSES.has(incident.status_code),
      );

      setIncidents(sortIncidentsForDisasterLink(filtered, linkedUuids));
    } catch {
      try {
        const allIncidents = await listOperationsIncidents();
        setIncidents(
          allIncidents.filter(
            (incident) => !TERMINAL_INCIDENT_STATUSES.has(incident.status_code),
          ),
        );
      } catch {
        setIncidents([]);
      }
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open || addPath !== "existing_incident" || !selectedDisasterUuid) return;
    void loadIncidents(selectedDisasterUuid);
  }, [open, addPath, selectedDisasterUuid, loadIncidents]);

  const handleDisasterLink = async (
    incidentUuid: string,
    path: AddPath,
  ): Promise<boolean> => {
    const linkResult = await submitLinkIncidentToDisaster(
      selectedDisasterUuid,
      incidentUuid,
    );

    if (linkResult.ok) return true;

    if (linkResult.status === 409) {
      toast.warning(
        "This incident may already be linked to the selected disaster.",
      );
      await onSuccess?.();
      setSuccessIncidentUuid(incidentUuid);
      return false;
    }

    toast.warning(
      path === "new_incident"
        ? "Incident created, but disaster linking failed. You can attach it from Incident Command."
        : "Report was linked to the incident, but disaster linking failed.",
    );
    setSuccessIncidentUuid(incidentUuid);
    return false;
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!item || !selectedDisasterUuid) return;

    if (locationMissing) {
      setSubmitError(
        "This report needs a valid reported location before it can be routed into disaster response.",
      );
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      let incidentUuid: string;

      if (addPath === "new_incident") {
        const data = await promoteIntakeReportToEmergency(item.id, {
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
          intakeReportPublicUuid: item.id,
          linkType,
          note: linkNote.trim() || undefined,
        });
        incidentUuid = existingIncidentUuid;
      }

      const linked = await handleDisasterLink(incidentUuid, addPath);

      if (linked) {
        toast.success(
          addPath === "new_incident"
            ? "Report promoted to emergency incident and linked to national disaster."
            : "Report linked through existing incident and attached to national disaster.",
        );
        await onSuccess?.();
        onClose();
      }
    } catch (err) {
      if (err instanceof ApiError) {
        const action = addPath === "new_incident" ? "emergency" : "link";
        let message = mapApiErrorToRouteMessage(err, action);
        if (
          err.code === "EMERGENCY_INCIDENT_REQUIRES_LOCATION" ||
          err.code === "INTAKE_NOT_PROMOTABLE"
        ) {
          if (err.code === "EMERGENCY_INCIDENT_REQUIRES_LOCATION") {
            message =
              "This report needs a valid reported location before it can be routed into disaster response.";
          }
        }
        if (
          err.code === "INTAKE_NOT_PROMOTABLE" ||
          err.code === "INTAKE_ALREADY_LINKED"
        ) {
          message = `${message} Try linking through an existing incident if applicable.`;
        }
        setSubmitError(message);
      } else {
        setSubmitError("Unable to route this report into disaster response.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open || !item) return null;

  const dialog = (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4 py-6">
      <form
        onSubmit={(event) => void handleSubmit(event)}
        className="flex max-h-[min(90vh,720px)] w-full max-w-2xl flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="triage-add-disaster-title"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="triage-add-disaster-title"
            className="text-lg font-semibold text-slate-900"
          >
            Add Report to National Disaster
          </h2>
          <p className="mt-0.5 text-xs text-slate-600">
            Choose how this report should enter disaster response. The report will
            be routed through an emergency incident before linking to the disaster.
          </p>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <ReportSummarySection item={item} />

          {locationMissing ? (
            <div className="rounded-lg border border-amber-200 bg-amber-50/80 px-3 py-2 text-sm text-amber-950">
              <p>
                This report needs a valid reported location before it can be routed
                into disaster response.
              </p>
              {onEditLocation ? (
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  className="mt-1.5"
                  onClick={onEditLocation}
                >
                  Edit Location
                </Button>
              ) : null}
            </div>
          ) : null}

          <DisasterSelectionSection
            disasters={activeDisasters}
            selectedDisasterUuid={selectedDisasterUuid}
            onSelect={setSelectedDisasterUuid}
            disabled={isSubmitting}
          />

          <fieldset className="space-y-2">
            <legend className="text-sm font-semibold text-slate-900">
              Routing Decision
            </legend>
            <label className="flex cursor-pointer items-start gap-2 text-sm text-slate-700">
              <input
                type="radio"
                name="triage-disaster-path"
                checked={addPath === "new_incident"}
                onChange={() => setAddPath("new_incident")}
                disabled={isSubmitting}
                className="mt-0.5 text-[#006747] focus:ring-[#006747]/30"
              />
              <span>Create a new emergency incident from this report</span>
            </label>
            <label className="flex cursor-pointer items-start gap-2 text-sm text-slate-700">
              <input
                type="radio"
                name="triage-disaster-path"
                checked={addPath === "existing_incident"}
                onChange={() => setAddPath("existing_incident")}
                disabled={isSubmitting}
                className="mt-0.5 text-[#006747] focus:ring-[#006747]/30"
              />
              <span>Link this report to an existing emergency incident</span>
            </label>
          </fieldset>

          {addPath === "new_incident" ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel htmlFor="triage-disaster-severity" required>
                  Severity
                </FieldLabel>
                <select
                  id="triage-disaster-severity"
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
                <FieldLabel htmlFor="triage-disaster-incident-title">
                  Incident title
                </FieldLabel>
                <input
                  id="triage-disaster-incident-title"
                  value={incidentTitle}
                  onChange={(event) => setIncidentTitle(event.target.value)}
                  className={triageFieldClassName}
                  disabled={isSubmitting}
                />
              </div>
              <div className="sm:col-span-2">
                <FieldLabel htmlFor="triage-disaster-incident-description">
                  Incident description
                </FieldLabel>
                <textarea
                  id="triage-disaster-incident-description"
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
                <FieldLabel htmlFor="triage-disaster-existing-incident" required>
                  Existing incident
                </FieldLabel>
                {incidentsLoading ? (
                  <p className="mt-1 text-sm text-slate-600">Loading incidents…</p>
                ) : (
                  <select
                    id="triage-disaster-existing-incident"
                    value={existingIncidentUuid}
                    onChange={(event) => setExistingIncidentUuid(event.target.value)}
                    className={triageFieldClassName}
                    disabled={isSubmitting || incidentsLoading}
                  >
                    <option value="">Select incident</option>
                    {incidents.map((incident) => (
                      <option key={incident.public_uuid} value={incident.public_uuid}>
                        {incident.incident_code ?? "—"} — {incident.title}
                        {LINKABLE_INCIDENT_STATUSES.has(incident.status_code)
                          ? ""
                          : ` (${formatBadgeLabel(formatIncidentStatus(incident.status_code))})`}
                      </option>
                    ))}
                  </select>
                )}
              </div>
              <div>
                <FieldLabel htmlFor="triage-disaster-link-type">Link type</FieldLabel>
                <select
                  id="triage-disaster-link-type"
                  value={linkType}
                  onChange={(event) =>
                    setLinkType(
                      event.target.value as LinkIntakeToIncidentPayload["linkType"],
                    )
                  }
                  className={triageFieldClassName}
                  disabled={isSubmitting}
                >
                  <option value="supporting_report">Supporting report</option>
                  <option value="follow_up_report">Follow-up report</option>
                </select>
              </div>
              <div>
                <FieldLabel htmlFor="triage-disaster-link-note">Note</FieldLabel>
                <textarea
                  id="triage-disaster-link-note"
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

        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={isSubmitting}
            onClick={onClose}
          >
            Cancel
          </Button>
          <button
            type="submit"
            disabled={
              isSubmitting ||
              !selectedDisasterUuid ||
              locationMissing ||
              (addPath === "existing_incident" &&
                (!existingIncidentUuid || incidentsLoading))
            }
            className={`${getDisasterOutlineButtonClasses()} disabled:cursor-not-allowed disabled:opacity-50`}
          >
            {isSubmitting ? "Routing…" : "Add to National Disaster"}
          </button>
        </div>
      </form>
    </div>
  );

  if (typeof document === "undefined") return null;
  return createPortal(dialog, document.body);
}
