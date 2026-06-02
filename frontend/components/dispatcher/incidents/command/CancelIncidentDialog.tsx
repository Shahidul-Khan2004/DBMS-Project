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

type CancelIncidentDialogProps = {
  open: boolean;
  incidentPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function CancelIncidentDialog({
  open,
  incidentPublicUuid,
  onClose,
  onSuccess,
}: CancelIncidentDialogProps) {
  const [note, setNote] = useState("");
  const [noteError, setNoteError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setNote("");
    setNoteError(null);
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    const trimmedNote = note.trim();
    if (!trimmedNote) {
      setNoteError("Cancellation reason is required.");
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);
    setNoteError(null);

    try {
      await patchIncidentStatus(incidentPublicUuid, {
        statusCode: "cancelled",
        outcomeCode: "cancelled",
        note: trimmedNote,
      });
      toast.success("Incident cancelled.");
      onClose();
      await onSuccess();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to cancel incident", err);
      }
      if (shouldRefreshDetailAfterIncidentStatusError(err)) {
        toast.error(mapPatchIncidentStatusError(err, "cancel"));
        onClose();
        await onSuccess();
        return;
      }
      setSubmitError(mapPatchIncidentStatusError(err, "cancel"));
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
        aria-labelledby="cancel-incident-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="cancel-incident-title"
            className="text-lg font-semibold text-slate-900"
          >
            Cancel Incident
          </h2>
          <p className="mt-2 text-sm leading-6 text-amber-800">
            Cancelling this incident will cancel remaining active unit dispatches
            and return busy units to available status.
          </p>
        </div>

        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="cancel-incident-note" required>
              Cancellation Reason
            </FieldLabel>
            <textarea
              id="cancel-incident-note"
              value={note}
              onChange={(event) => {
                setNote(event.target.value);
                if (noteError) setNoteError(null);
              }}
              placeholder="Explain why this incident is being cancelled"
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
            Keep Incident
          </Button>
          <Button
            type="button"
            variant="danger"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={isSubmitting}
          >
            {isSubmitting ? "Cancelling..." : "Cancel Incident"}
          </Button>
        </div>
      </div>
    </div>
  );
}
