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
  mapUpdateDispatchStatusError,
  shouldRefreshDetailAfterDispatchStatusError,
} from "@/lib/incident-command-api-errors";
import { updateOperationsDispatchStatus } from "@/lib/operations-incident-api";
import type {
  DispatchStatusAction,
  IncidentDispatch,
} from "@/types/incident-command";

type DispatchStatusActionDialogProps = {
  open: boolean;
  dispatch: IncidentDispatch | null;
  targetStatus: DispatchStatusAction | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

const PROGRESS_TITLES: Record<
  Exclude<DispatchStatusAction, "cancelled">,
  string
> = {
  dispatched: "Mark Dispatched",
  arrived: "Mark Arrived",
  completed: "Mark Completed",
};

const SUCCESS_TOASTS: Record<DispatchStatusAction, string> = {
  dispatched: "Unit marked as dispatched.",
  arrived: "Unit marked as arrived.",
  completed: "Dispatch completed.",
  cancelled: "Dispatch cancelled.",
};

export function DispatchStatusActionDialog({
  open,
  dispatch,
  targetStatus,
  onClose,
  onSuccess,
}: DispatchStatusActionDialogProps) {
  const [note, setNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isCancellation = targetStatus === "cancelled";
  const requiresNote = isCancellation;
  const canSubmit =
    Boolean(dispatch?.publicUuid && targetStatus) &&
    (!requiresNote || note.trim().length > 0);

  useEffect(() => {
    if (!open) return;
    setNote("");
    setSubmitError(null);
  }, [open, dispatch?.publicUuid, targetStatus]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    if (!dispatch?.publicUuid || !targetStatus || !canSubmit) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await updateOperationsDispatchStatus(dispatch.publicUuid, {
        statusCode: targetStatus,
        note: note.trim() || undefined,
      });
      toast.success(SUCCESS_TOASTS[targetStatus]);
      onClose();
      await onSuccess();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to update dispatch status", err);
      }
      if (shouldRefreshDetailAfterDispatchStatusError(err)) {
        toast.error(mapUpdateDispatchStatusError(err));
        onClose();
        await onSuccess();
        return;
      }
      setSubmitError(mapUpdateDispatchStatusError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open || !dispatch || !targetStatus) return null;

  const title = isCancellation
    ? "Cancel Dispatch"
    : PROGRESS_TITLES[targetStatus];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex w-full max-w-md flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="dispatch-status-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="dispatch-status-title"
            className="text-lg font-semibold text-slate-900"
          >
            {title}
          </h2>
          <p className="mt-2 text-sm text-slate-600">
            <span className="font-medium text-slate-800">{dispatch.unitName}</span>
            <span className="text-slate-400"> · </span>
            {dispatch.owningAgencyName}
          </p>
          {isCancellation ? (
            <p className="mt-2 text-sm leading-6 text-amber-800">
              This will end this unit assignment and return the unit to available
              status.
            </p>
          ) : null}
        </div>

        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel
              htmlFor="dispatch-status-note"
              required={isCancellation}
            >
              {isCancellation ? "Cancellation Note" : "Operational Note"}
            </FieldLabel>
            <textarea
              id="dispatch-status-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder={
                isCancellation
                  ? "Explain why this dispatch is being cancelled"
                  : "Add operational context (optional)"
              }
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
            variant={isCancellation ? "danger" : "primary"}
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={!canSubmit || isSubmitting}
          >
            {isSubmitting ? "Saving..." : title}
          </Button>
        </div>
      </div>
    </div>
  );
}
