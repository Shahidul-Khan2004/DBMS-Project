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

type ResolveIncidentDialogProps = {
  open: boolean;
  incidentPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function ResolveIncidentDialog({
  open,
  incidentPublicUuid,
  onClose,
  onSuccess,
}: ResolveIncidentDialogProps) {
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
      setNoteError("Resolution note is required.");
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);
    setNoteError(null);

    try {
      await patchIncidentStatus(incidentPublicUuid, {
        statusCode: "resolved",
        outcomeCode: "resolved",
        note: trimmedNote,
      });
      toast.success("Incident resolved.");
      onClose();
      await onSuccess();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to resolve incident", err);
      }
      if (shouldRefreshDetailAfterIncidentStatusError(err)) {
        toast.error(mapPatchIncidentStatusError(err, "resolve"));
        onClose();
        await onSuccess();
        return;
      }
      setSubmitError(mapPatchIncidentStatusError(err, "resolve"));
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
        aria-labelledby="resolve-incident-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="resolve-incident-title"
            className="text-lg font-semibold text-slate-900"
          >
            Resolve Incident
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            Confirm that response operations are complete and this incident has
            been resolved.
          </p>
          <p className="mt-2 text-sm leading-6 text-amber-800">
            Any remaining active unit dispatches will be completed by the system
            and busy units returned to available status.
          </p>
        </div>

        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="resolve-incident-note" required>
              Resolution Note
            </FieldLabel>
            <textarea
              id="resolve-incident-note"
              value={note}
              onChange={(event) => {
                setNote(event.target.value);
                if (noteError) setNoteError(null);
              }}
              placeholder="Describe how the incident was resolved"
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
            {isSubmitting ? "Resolving..." : "Resolve Incident"}
          </Button>
        </div>
      </div>
    </div>
  );
}
