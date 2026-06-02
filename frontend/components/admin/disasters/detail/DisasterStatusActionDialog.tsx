"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postDisasterStatus } from "@/lib/disaster-operations-api";
import type { DisasterLifecycleAction } from "@/lib/disaster-operations-format";

const COPY: Record<
  DisasterLifecycleAction,
  { title: string; description: string; confirm: string; statusCode: "resolved" | "closed" | "cancelled" }
> = {
  resolve: {
    title: "Resolve Disaster",
    description:
      "Mark the disaster as resolved when response operations are winding down. Open linked incidents and relief requests must be closed first.",
    confirm: "Resolve Disaster",
    statusCode: "resolved",
  },
  close: {
    title: "Close Disaster",
    description:
      "Permanently close this disaster record. Active shelter and relief hub activations will be finalized.",
    confirm: "Close Disaster",
    statusCode: "closed",
  },
  cancel: {
    title: "Cancel Disaster",
    description:
      "Cancel this disaster event. Active activations will be finalized.",
    confirm: "Cancel Disaster",
    statusCode: "cancelled",
  },
};

type DisasterStatusActionDialogProps = {
  open: boolean;
  action: DisasterLifecycleAction;
  disasterPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function DisasterStatusActionDialog({
  open,
  action,
  disasterPublicUuid,
  onClose,
  onSuccess,
}: DisasterStatusActionDialogProps) {
  const copy = COPY[action];
  const [note, setNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setNote("");
    setSubmitError(null);
  }, [open, action]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postDisasterStatus(disasterPublicUuid, {
        statusCode: copy.statusCode,
        note: note.trim() || undefined,
      });
      toast.success(`Disaster ${copy.statusCode}.`);
      onClose();
      await onSuccess();
    } catch (err) {
      const message =
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to update disaster status.";
      setSubmitError(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex w-full max-w-md flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">{copy.title}</h2>
          <p className="mt-2 text-sm leading-6 text-slate-600">{copy.description}</p>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="disaster-status-note">Note (optional)</FieldLabel>
            <textarea
              id="disaster-status-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={500}
              rows={3}
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
            variant={action === "cancel" ? "danger" : "primary"}
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={isSubmitting}
          >
            {copy.confirm}
          </Button>
        </div>
      </div>
    </div>
  );
}
