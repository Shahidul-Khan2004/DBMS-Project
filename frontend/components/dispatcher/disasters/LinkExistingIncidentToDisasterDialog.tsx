"use client";

import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { toast } from "sonner";
import { getDisasterOutlineButtonClasses } from "@/components/dispatcher/disasters/disasterColors";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import {
  listCandidateDisasterIncidents,
  sortIncidentsByAffectedAreaMatch,
} from "@/lib/disaster-dispatcher-api";
import { listOperationsDisasters } from "@/lib/disaster-operations-api";
import { filterDispatcherActiveDisasters } from "@/lib/disaster-operations-format";
import { submitLinkIncidentToDisaster } from "@/lib/disaster-link-submit";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import {
  getOperationsIncidents,
  LINKABLE_INCIDENT_STATUSES,
  TERMINAL_INCIDENT_STATUSES,
  type OperationsIncidentRow,
} from "@/lib/operations-intake-triage";
import type { OperationsDisasterSummary } from "@/lib/disaster-operations-types";
import { formatIncidentStatus } from "@/lib/incident-status";

type LinkExistingIncidentToDisasterDialogProps =
  | {
      open: boolean;
      mode: "pick-incident";
      disasterPublicUuid: string;
      dashboard?: OperationsDisasterDashboard;
      incidentPublicUuid?: never;
      onClose: () => void;
      onSuccess?: () => void | Promise<void>;
    }
  | {
      open: boolean;
      mode: "pick-disaster";
      incidentPublicUuid: string;
      disasterPublicUuid?: never;
      dashboard?: never;
      onClose: () => void;
      onSuccess?: () => void | Promise<void>;
    };

function matchesIncidentSearch(incident: OperationsIncidentRow, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  const haystack = [
    incident.incident_code,
    incident.title,
    incident.category_code,
    incident.status_code,
    incident.location?.address_text,
    incident.location?.place_name,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(normalized);
}

export function LinkExistingIncidentToDisasterDialog(
  props: LinkExistingIncidentToDisasterDialogProps,
) {
  const { open, onClose, onSuccess } = props;

  const [disasters, setDisasters] = useState<OperationsDisasterSummary[]>([]);
  const [incidents, setIncidents] = useState<OperationsIncidentRow[]>([]);
  const [selectedDisasterUuid, setSelectedDisasterUuid] = useState("");
  const [selectedIncidentUuid, setSelectedIncidentUuid] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isPickIncident = props.mode === "pick-incident";
  const fixedDisasterUuid = isPickIncident ? props.disasterPublicUuid : null;
  const fixedIncidentUuid = !isPickIncident ? props.incidentPublicUuid : null;
  const dashboard = isPickIncident ? props.dashboard : undefined;

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setSubmitError(null);
    try {
      if (isPickIncident) {
        if (dashboard) {
          const candidates = await listCandidateDisasterIncidents(dashboard);
          setIncidents(sortIncidentsByAffectedAreaMatch(candidates, dashboard));
        } else {
          const data = await getOperationsIncidents({ limit: 100, offset: 0 });
          setIncidents(
            (data.incidents ?? []).filter(
              (incident) => !TERMINAL_INCIDENT_STATUSES.has(incident.status_code),
            ),
          );
        }
      } else {
        const data = await listOperationsDisasters();
        setDisasters(filterDispatcherActiveDisasters(data));
      }
    } catch {
      if (isPickIncident) {
        setIncidents([]);
        setSubmitError("Unable to load incidents.");
      } else {
        setDisasters([]);
      }
    } finally {
      setIsLoading(false);
    }
  }, [isPickIncident, dashboard]);

  useEffect(() => {
    if (!open) return;
    setSelectedDisasterUuid("");
    setSelectedIncidentUuid("");
    setSearchQuery("");
    setSubmitError(null);
    void loadData();
  }, [open, loadData]);

  const filteredIncidents = useMemo(
    () => incidents.filter((incident) => matchesIncidentSearch(incident, searchQuery)),
    [incidents, searchQuery],
  );

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const disasterUuid = fixedDisasterUuid ?? selectedDisasterUuid;
    const incidentUuid = fixedIncidentUuid ?? selectedIncidentUuid;

    if (!disasterUuid || !incidentUuid) {
      setSubmitError(
        isPickIncident ? "Select an incident to link." : "Select an active disaster.",
      );
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    const result = await submitLinkIncidentToDisaster(disasterUuid, incidentUuid);

    if (result.ok) {
      toast.success("Incident linked to disaster.");
      onClose();
      await onSuccess?.();
    } else {
      setSubmitError(result.message);
      if (result.status === 409) {
        await onSuccess?.();
      }
    }

    setIsSubmitting(false);
  };

  if (!open) return null;

  const title = isPickIncident ? "Link Existing Incident" : "Attach to Disaster";
  const subtitle = isPickIncident
    ? "Select an active emergency incident to link to this disaster."
    : "Link this emergency incident to an active national disaster protocol.";

  const dialog = (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4 py-6">
      <form
        onSubmit={(event) => void handleSubmit(event)}
        className="flex max-h-[min(90vh,640px)] w-full max-w-lg flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="link-incident-disaster-title"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2 id="link-incident-disaster-title" className="text-lg font-semibold text-slate-900">
            {title}
          </h2>
          <p className="mt-0.5 text-xs text-slate-600">{subtitle}</p>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {submitError ? <ErrorAlert message={submitError} /> : null}

          {isPickIncident ? (
            <>
              <label className="block">
                <span className="mb-1 block text-sm font-medium text-slate-700">
                  Search incidents
                </span>
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Incident code, title, status…"
                  className={triageFieldClassName}
                  disabled={isSubmitting || isLoading}
                />
              </label>
              {isLoading ? (
                <p className="text-sm text-slate-600">Loading incidents…</p>
              ) : filteredIncidents.length === 0 ? (
                <p className="text-sm text-slate-600">
                  No linkable incidents available for this disaster.
                </p>
              ) : (
                <ul className="max-h-64 space-y-2 overflow-y-auto pr-1">
                  {filteredIncidents.map((incident) => {
                    const selected = selectedIncidentUuid === incident.public_uuid;
                    const isActive = LINKABLE_INCIDENT_STATUSES.has(incident.status_code);
                    return (
                      <li key={incident.public_uuid}>
                        <button
                          type="button"
                          disabled={isSubmitting}
                          onClick={() => setSelectedIncidentUuid(incident.public_uuid)}
                          className={`w-full rounded-lg border px-3 py-2.5 text-left ${getDispatcherSelectableRowClasses({
                            selected,
                            disabled: isSubmitting,
                            variant: "flat",
                          })}`}
                        >
                          <p className="text-sm font-semibold text-slate-900">
                            {incident.title?.trim() || "Untitled incident"}
                          </p>
                          <p className="mt-0.5 text-xs text-slate-600">
                            {incident.incident_code ?? "—"}
                            {incident.location?.place_name
                              ? ` · ${incident.location.place_name}`
                              : ""}
                          </p>
                          <p className="mt-1 text-xs text-slate-500">
                            {formatBadgeLabel(formatIncidentStatus(incident.status_code))}
                            {!isActive ? " · Non-active" : ""}
                          </p>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </>
          ) : isLoading ? (
            <p className="text-sm text-slate-600">Loading active disasters…</p>
          ) : disasters.length === 0 ? (
            <p className="text-sm text-slate-600">
              No active national disaster protocol is available for linking.
            </p>
          ) : (
            <div>
              <FieldLabel htmlFor="attach-disaster-select">Active disaster</FieldLabel>
              <select
                id="attach-disaster-select"
                value={selectedDisasterUuid}
                disabled={isSubmitting}
                onChange={(event) => setSelectedDisasterUuid(event.target.value)}
                className={`mt-1 ${triageFieldClassName}`}
              >
                <option value="">Select an active disaster</option>
                {disasters.map((disaster) => (
                  <option key={disaster.public_uuid} value={disaster.public_uuid}>
                    {disaster.event_code} — {disaster.title}
                  </option>
                ))}
              </select>
            </div>
          )}
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
              isLoading ||
              (isPickIncident
                ? !selectedIncidentUuid
                : disasters.length === 0 || !selectedDisasterUuid)
            }
            className={`${getDisasterOutlineButtonClasses()} disabled:cursor-not-allowed disabled:opacity-50`}
          >
            {isSubmitting ? "Linking…" : isPickIncident ? "Link to Disaster" : "Attach"}
          </button>
        </div>
      </form>
    </div>
  );

  if (typeof document === "undefined") return null;
  return createPortal(dialog, document.body);
}

/** @deprecated Use LinkExistingIncidentToDisasterDialog with mode="pick-disaster" */
export function AttachIncidentToDisasterDialog({
  open,
  incidentPublicUuid,
  onClose,
  onSuccess,
}: {
  open: boolean;
  incidentPublicUuid: string;
  onClose: () => void;
  onSuccess?: () => void | Promise<void>;
}) {
  return (
    <LinkExistingIncidentToDisasterDialog
      open={open}
      mode="pick-disaster"
      incidentPublicUuid={incidentPublicUuid}
      onClose={onClose}
      onSuccess={onSuccess}
    />
  );
}
