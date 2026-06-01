"use client";

import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import type { ServiceCaseStatusActionTarget } from "@/components/dispatcher/service-cases/detail/serviceCaseActions";
import { statusActionDialogDescription } from "@/components/dispatcher/service-cases/detail/serviceCaseActions";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { patchOperationsServiceCaseStatus } from "@/lib/service-case-api";

type ServiceCaseStatusActionDialogProps = {
  open: boolean;
  casePublicUuid: string;
  title: string;
  targetStatus: ServiceCaseStatusActionTarget;
  confirmLabel: string;
  description?: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function ServiceCaseStatusActionDialog({
  open,
  casePublicUuid,
  title,
  targetStatus,
  confirmLabel,
  description,
  onClose,
  onSuccess,
}: ServiceCaseStatusActionDialogProps) {
  const [note, setNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setNote("");
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (isSubmitting) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await patchOperationsServiceCaseStatus(casePublicUuid, {
        statusCode: targetStatus,
        note: note.trim() || undefined,
      });
      toast.success(`Case ${confirmLabel.toLowerCase()} completed.`);
      onClose();
      await onSuccess();
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not update case status.";
      setSubmitError(message);
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
        aria-labelledby="service-case-status-action-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="service-case-status-action-title"
            className="text-lg font-semibold text-slate-900"
          >
            {title}
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            {description ?? statusActionDialogDescription(targetStatus)}
          </p>
        </div>

        <form onSubmit={(event) => void handleSubmit(event)} className="flex flex-col">
          <div className="space-y-4 px-5 py-4">
            {submitError ? <ErrorAlert message={submitError} /> : null}
            <div>
              <FieldLabel htmlFor="service-case-status-note">Note</FieldLabel>
              <textarea
                id="service-case-status-note"
                value={note}
                onChange={(event) => setNote(event.target.value)}
                className={triageFieldClassName}
                rows={3}
                maxLength={500}
                placeholder="Optional note for the status change"
                disabled={isSubmitting}
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={handleClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              isLoading={isSubmitting}
              disabled={isSubmitting}
            >
              {confirmLabel}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
