"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import {
  mapPatchIncidentStatusError,
  shouldRefreshDetailAfterIncidentStatusError,
} from "@/lib/incident-command-api-errors";
import { patchIncidentStatus } from "@/lib/operations-incident-api";
import type { PatchIncidentStatusPayload } from "@/types/operations-incident";

type CloseOutcomeCode = Exclude<
  PatchIncidentStatusPayload["outcomeCode"],
  "cancelled"
>;

const OUTCOME_OPTIONS: { label: string; value: CloseOutcomeCode }[] = [
  { label: "Resolved", value: "resolved" },
  { label: "False Alarm", value: "false_alarm" },
  { label: "Duplicate Incident", value: "duplicate_incident" },
  { label: "Transferred", value: "transferred" },
  { label: "Unresolved", value: "unresolved" },
];

type CloseIncidentDialogProps = {
  open: boolean;
  incidentPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function CloseIncidentDialog({
  open,
  incidentPublicUuid,
  onClose,
  onSuccess,
}: CloseIncidentDialogProps) {
  const [outcomeCode, setOutcomeCode] = useState<CloseOutcomeCode>("resolved");
  const [note, setNote] = useState("");
  const [outcomeError, setOutcomeError] = useState<string | null>(null);
  const [noteError, setNoteError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setOutcomeCode("resolved");
    setNote("");
    setOutcomeError(null);
    setNoteError(null);
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    let hasError = false;
    if (!outcomeCode) {
      setOutcomeError("Final outcome is required.");
      hasError = true;
    }
    const trimmedNote = note.trim();
    if (!trimmedNote) {
      setNoteError("Closure note is required.");
      hasError = true;
    }
    if (hasError) return;

    setIsSubmitting(true);
    setSubmitError(null);
    setOutcomeError(null);
    setNoteError(null);

    try {
      await patchIncidentStatus(incidentPublicUuid, {
        statusCode: "closed",
        outcomeCode,
        note: trimmedNote,
      });
      toast.success("Incident closed.");
      onClose();
      await onSuccess();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to close incident", err);
      }
      if (shouldRefreshDetailAfterIncidentStatusError(err)) {
        toast.error(mapPatchIncidentStatusError(err, "close"));
        onClose();
        await onSuccess();
        return;
      }
      setSubmitError(mapPatchIncidentStatusError(err, "close"));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex w-full max-w-md flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="close-incident-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="close-incident-title"
            className="text-lg font-semibold text-slate-900"
          >
            Close Incident
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            Select the final outcome and record why this incident is being closed.
          </p>
          <p className="mt-2 text-sm leading-6 text-amber-800">
            Remaining active unit dispatches will be completed and busy units
            returned to available status.
          </p>
        </div>

        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="close-outcome" required>
              Final Outcome
            </FieldLabel>
            <select
              id="close-outcome"
              value={outcomeCode}
              onChange={(event) => {
                setOutcomeCode(event.target.value as CloseOutcomeCode);
                if (outcomeError) setOutcomeError(null);
              }}
              className={triageFieldClassName}
              disabled={isSubmitting}
            >
              {OUTCOME_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            {outcomeError ? (
              <p className="mt-1 text-sm text-[#991B1B]">{outcomeError}</p>
            ) : null}
          </div>

          <div>
            <FieldLabel htmlFor="close-note" required>
              Closure Note
            </FieldLabel>
            <textarea
              id="close-note"
              value={note}
              onChange={(event) => {
                setNote(event.target.value);
                if (noteError) setNoteError(null);
              }}
              placeholder="Explain the final outcome and why this incident is being closed"
              rows={3}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
            {noteError ? (
              <p className="mt-1 text-sm text-[#991B1B]">{noteError}</p>
            ) : null}
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
            variant="primary"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={isSubmitting}
          >
            {isSubmitting ? "Closing..." : "Close Incident"}
          </Button>
        </div>
      </div>
    </div>
  );
}
