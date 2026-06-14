"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { FieldLabel, FieldLegend } from "@/components/dispatcher/FieldLabel";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError } from "@/lib/api";
import {
  mapCreateDispatchError,
  shouldRefreshAvailableUnitsAfterCreateDispatchError,
} from "@/lib/incident-command-api-errors";
import { formatIncidentField } from "@/lib/operations-incident-format";
import {
  createIncidentDispatch,
  getAvailableUnitsForIncident,
} from "@/lib/operations-incident-api";
import type {
  DispatchPriorityLevel,
} from "@/types/incident-command";
import type { AvailableIncidentUnit } from "@/types/operations-incident";

const PRIORITY_OPTIONS: Array<{
  value: DispatchPriorityLevel;
  label: string;
}> = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
];

type DispatchUnitDialogProps = {
  open: boolean;
  incidentPublicUuid: string;
  incidentTitle: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

function filterUnits(units: AvailableIncidentUnit[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return units;

  return units.filter((unit) => {
    const haystack = [
      unit.unit_name,
      unit.unit_code,
      unit.agency_name,
      unit.unit_type_code,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(normalized);
  });
}

export function DispatchUnitDialog({
  open,
  incidentPublicUuid,
  incidentTitle,
  onClose,
  onSuccess,
}: DispatchUnitDialogProps) {
  const [units, setUnits] = useState<AvailableIncidentUnit[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedUnitUuid, setSelectedUnitUuid] = useState<string | null>(null);
  const [priorityLevel, setPriorityLevel] =
    useState<DispatchPriorityLevel>("medium");
  const [note, setNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const filteredUnits = useMemo(
    () => filterUnits(units, searchQuery),
    [units, searchQuery],
  );

  const loadUnits = useCallback(async () => {
    setLoading(true);
    setLoadError(null);

    try {
      const response = await getAvailableUnitsForIncident(incidentPublicUuid, {
        sort: "distance_asc",
        includeDistance: true,
      });
      setUnits(response.units ?? []);
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load available units", err);
      }
      if (err instanceof ApiError && err.code === "INCIDENT_NOT_FOUND") {
        setLoadError("This incident could not be found.");
      } else if (err instanceof ApiError && err.code === "VALIDATION_ERROR") {
        setLoadError(
          "Unable to load or create dispatch because required information is invalid.",
        );
      } else {
        setLoadError("Unable to load available units. Try again.");
      }
      setUnits([]);
    } finally {
      setLoading(false);
    }
  }, [incidentPublicUuid]);

  useEffect(() => {
    if (!open) return;
    setSearchQuery("");
    setSelectedUnitUuid(null);
    setPriorityLevel("medium");
    setNote("");
    setSubmitError(null);
    void loadUnits();
  }, [open, loadUnits]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    if (!selectedUnitUuid) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await createIncidentDispatch(incidentPublicUuid, {
        unitPublicUuid: selectedUnitUuid,
        priorityLevel,
        note: note.trim() || undefined,
      });
      toast.success("Unit assigned for dispatch.");
      onClose();
      await onSuccess();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to create dispatch", err);
      }
      setSubmitError(mapCreateDispatchError(err));
      if (shouldRefreshAvailableUnitsAfterCreateDispatchError(err)) {
        setSelectedUnitUuid(null);
        void loadUnits();
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="dispatch-unit-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="dispatch-unit-title"
            className="text-lg font-semibold text-slate-900"
          >
            Dispatch Unit
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Assign a unit to: {incidentTitle}
          </p>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <FieldLabel htmlFor="dispatch-unit-search">Search available units</FieldLabel>
          <input
            id="dispatch-unit-search"
            type="search"
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Search available units"
            className={triageFieldClassName}
          />

          <FieldLegend required>Select Unit</FieldLegend>

          {loading ? (
            <LoadingSkeleton lines={4} />
          ) : loadError ? (
            <div className="space-y-2">
              <ErrorAlert message={loadError} />
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => void loadUnits()}
              >
                Retry
              </Button>
            </div>
          ) : filteredUnits.length === 0 ? (
            <div className="space-y-1">
              <p className="text-sm text-slate-600">
                No available units from participating agencies.
              </p>
              <p className="text-xs text-slate-500">
                Assign another agency or wait for a unit to become available.
              </p>
            </div>
          ) : (
            <ul className="space-y-2">
              {filteredUnits.map((unit) => {
                const selected = selectedUnitUuid === unit.public_uuid;

                return (
                  <li key={unit.public_uuid}>
                    <button
                      type="button"
                      onClick={() => setSelectedUnitUuid(unit.public_uuid)}
                      className={`w-full rounded-xl border p-3 text-left ${getDispatcherSelectableRowClasses({ selected, variant: "flat" })}`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-sm font-semibold text-slate-900">
                          {unit.unit_name}
                        </p>
                        <Badge tone="available">Available</Badge>
                        {unit.distance_km != null ? (
                          <span className="text-xs text-slate-500">
                            {unit.distance_km.toFixed(1)} km
                          </span>
                        ) : null}
                      </div>
                      <p className="mt-1 text-xs text-slate-600">
                        {unit.unit_code} · {formatIncidentField(unit.unit_type_code)} ·{" "}
                        {unit.agency_name}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          <div>
            <FieldLabel htmlFor="dispatch-priority">Priority</FieldLabel>
            <select
              id="dispatch-priority"
              value={priorityLevel}
              onChange={(event) =>
                setPriorityLevel(event.target.value as DispatchPriorityLevel)
              }
              className={triageFieldClassName}
            >
              {PRIORITY_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <FieldLabel htmlFor="dispatch-note">Dispatch Note</FieldLabel>
            <textarea
              id="dispatch-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Add operational instruction or context (optional)"
              rows={3}
              className={triageFieldClassName}
            />
          </div>

          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>

        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button
            type="button"
            variant="secondary"
            onClick={handleClose}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={!selectedUnitUuid || isSubmitting}
          >
            {isSubmitting ? "Dispatching..." : "Dispatch Unit"}
          </Button>
        </div>
      </div>
    </div>
  );
}
