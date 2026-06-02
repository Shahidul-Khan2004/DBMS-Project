"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { FieldLabel, FieldLegend } from "@/components/dispatcher/FieldLabel";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { mapAssignAgencyError } from "@/lib/incident-command-api-errors";
import {
  assignAgencyToIncident,
  getOperationsAgenciesWorkload,
} from "@/lib/operations-incident-api";
import type { OperationsAgencyWorkloadItem } from "@/types/operations-incident";

type AssignParticipatingAgencyDialogProps = {
  open: boolean;
  incidentPublicUuid: string;
  incidentTitle: string;
  participatingAgencyUuids: string[];
  hasLeadAgency: boolean;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

function filterAgencies(
  agencies: OperationsAgencyWorkloadItem[],
  query: string,
) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return agencies;
  return agencies.filter((agency) =>
    agency.agency_name.toLowerCase().includes(normalized),
  );
}

export function AssignParticipatingAgencyDialog({
  open,
  incidentPublicUuid,
  incidentTitle,
  participatingAgencyUuids,
  hasLeadAgency,
  onClose,
  onSuccess,
}: AssignParticipatingAgencyDialogProps) {
  const [agencies, setAgencies] = useState<OperationsAgencyWorkloadItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedAgencyUuid, setSelectedAgencyUuid] = useState<string | null>(
    null,
  );
  const [isLeadAgency, setIsLeadAgency] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const participatingSet = useMemo(
    () => new Set(participatingAgencyUuids),
    [participatingAgencyUuids],
  );

  const filteredAgencies = useMemo(
    () => filterAgencies(agencies, searchQuery),
    [agencies, searchQuery],
  );

  const loadAgencies = useCallback(async () => {
    setLoading(true);
    setLoadError(null);

    try {
      const response = await getOperationsAgenciesWorkload();
      setAgencies(response.agencies ?? []);
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load agency workload", err);
      }
      setLoadError("Unable to load agencies. Try again.");
      setAgencies([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    setSearchQuery("");
    setSelectedAgencyUuid(null);
    setIsLeadAgency(false);
    setSubmitError(null);
    void loadAgencies();
  }, [open, loadAgencies]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    if (!selectedAgencyUuid) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await assignAgencyToIncident(incidentPublicUuid, {
        agencyPublicUuid: selectedAgencyUuid,
        isLeadAgency: hasLeadAgency ? false : isLeadAgency,
      });
      toast.success("Agency assigned to incident.");
      onClose();
      await onSuccess();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to assign agency", err);
      }
      setSubmitError(mapAssignAgencyError(err));
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
        aria-labelledby="assign-agency-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="assign-agency-title"
            className="text-lg font-semibold text-slate-900"
          >
            Assign Participating Agency
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Assign an agency to: {incidentTitle}
          </p>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <FieldLabel htmlFor="assign-agency-search">Search agencies</FieldLabel>
          <input
            id="assign-agency-search"
            type="search"
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Search agencies"
            className={triageFieldClassName}
          />

          <FieldLegend required>Select Agency</FieldLegend>

          {loading ? (
            <LoadingSkeleton lines={4} />
          ) : loadError ? (
            <div className="space-y-2">
              <ErrorAlert message={loadError} />
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => void loadAgencies()}
              >
                Retry
              </Button>
            </div>
          ) : filteredAgencies.length === 0 ? (
            <p className="text-sm text-slate-600">No agencies match your search.</p>
          ) : (
            <ul className="space-y-2">
              {filteredAgencies.map((agency) => {
                const alreadyParticipating = participatingSet.has(
                  agency.agency_public_uuid,
                );
                const selected = selectedAgencyUuid === agency.agency_public_uuid;

                return (
                  <li key={agency.agency_public_uuid}>
                    <button
                      type="button"
                      disabled={alreadyParticipating}
                      onClick={() =>
                        setSelectedAgencyUuid(agency.agency_public_uuid)
                      }
                      className={`w-full rounded-xl border p-3 text-left ${getDispatcherSelectableRowClasses({
                        selected,
                        disabled: alreadyParticipating,
                        variant: "flat",
                      })}`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-sm font-semibold text-slate-900">
                          {agency.agency_name}
                        </p>
                        {alreadyParticipating ? (
                          <span className="inline-flex rounded-full bg-slate-200 px-2 py-0.5 text-xs font-medium text-slate-700">
                            Already participating
                          </span>
                        ) : null}
                      </div>
                      <p className="mt-1 text-xs text-slate-600">
                        Available units: {agency.available_units} of{" "}
                        {agency.total_units}
                      </p>
                      <p className="text-xs text-slate-600">
                        Busy units: {agency.busy_units}
                      </p>
                      <p className="text-xs text-slate-600">
                        Active incidents: {agency.active_incidents}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={isLeadAgency}
              disabled={hasLeadAgency}
              onChange={(event) => setIsLeadAgency(event.target.checked)}
              className="mt-1 h-4 w-4 rounded border-slate-300 text-[#002D62] focus:ring-[#002D62]"
            />
            <span className="text-sm text-slate-700">
              Assign as lead agency
              {hasLeadAgency ? (
                <span className="mt-1 block text-xs text-slate-500">
                  A lead agency is already assigned to this incident.
                </span>
              ) : null}
            </span>
          </label>

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
            disabled={!selectedAgencyUuid || isSubmitting}
          >
            {isSubmitting ? "Assigning..." : "Assign Agency"}
          </Button>
        </div>
      </div>
    </div>
  );
}
