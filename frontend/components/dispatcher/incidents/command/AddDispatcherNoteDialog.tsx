"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { addIncidentOperationalNote } from "@/lib/operations-incident-api";

const TITLE_MAX_LENGTH = 255;
const SUBMIT_ERROR_MESSAGE = "Unable to add dispatcher note. Try again.";

type AddDispatcherNoteDialogProps = {
  open: boolean;
  incidentPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AddDispatcherNoteDialog({
  open,
  incidentPublicUuid,
  onClose,
  onSuccess,
}: AddDispatcherNoteDialogProps) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [titleError, setTitleError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setTitle("");
    setDescription("");
    setTitleError(null);
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    const trimmedTitle = title.trim();
    const trimmedDescription = description.trim();

    if (!trimmedTitle) {
      setTitleError("Note title is required.");
      return;
    }

    if (trimmedTitle.length > TITLE_MAX_LENGTH) {
      setTitleError(`Note title must be ${TITLE_MAX_LENGTH} characters or fewer.`);
      return;
    }

    setTitleError(null);
    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await addIncidentOperationalNote(incidentPublicUuid, {
        title: trimmedTitle,
        description: trimmedDescription || undefined,
      });
      toast.success("Dispatcher note added.");
      onClose();
      await onSuccess();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to add dispatcher note", err);
      }
      setSubmitError(SUBMIT_ERROR_MESSAGE);
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
        aria-labelledby="add-dispatcher-note-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="add-dispatcher-note-title"
            className="text-lg font-semibold text-slate-900"
          >
            Add Dispatcher Note
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Record an operational observation or decision for this incident.
          </p>
        </div>

        <div className="space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel htmlFor="dispatcher-note-title" required>
              Note Title
            </FieldLabel>
            <input
              id="dispatcher-note-title"
              type="text"
              value={title}
              onChange={(event) => {
                setTitle(event.target.value);
                if (titleError) setTitleError(null);
              }}
              maxLength={TITLE_MAX_LENGTH}
              placeholder="e.g. Additional medical support requested"
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
            {titleError ? (
              <p className="mt-1 text-xs text-red-600">{titleError}</p>
            ) : null}
          </div>

          <div>
            <FieldLabel htmlFor="dispatcher-note-details">Details</FieldLabel>
            <textarea
              id="dispatcher-note-details"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Add relevant context, instructions or observations (optional)"
              rows={4}
              className={triageFieldClassName}
              disabled={isSubmitting}
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
            disabled={isSubmitting}
          >
            {isSubmitting ? "Adding..." : "Add Note"}
          </Button>
        </div>
      </div>
    </div>
  );
}
