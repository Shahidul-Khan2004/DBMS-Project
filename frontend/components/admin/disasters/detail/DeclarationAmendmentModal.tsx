"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postDisasterDeclarationAmendment } from "@/lib/disaster-operations-api";

type DeclarationAmendmentModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function DeclarationAmendmentModal({
  open,
  disasterPublicUuid,
  onClose,
  onSuccess,
}: DeclarationAmendmentModalProps) {
  const [title, setTitle] = useState("");
  const [reason, setReason] = useState("");
  const [publicGuidance, setPublicGuidance] = useState("");
  const [legalReference, setLegalReference] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setTitle("");
    setReason("");
    setPublicGuidance("");
    setLegalReference("");
    setSubmitError(null);
  }, [open]);

  if (!open) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!title.trim() || !reason.trim()) {
      setSubmitError("Title and reason are required.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postDisasterDeclarationAmendment(disasterPublicUuid, {
        title: title.trim(),
        reason: reason.trim(),
        publicGuidance: publicGuidance.trim() || undefined,
        legalReference: legalReference.trim() || undefined,
      });
      toast.success("Declaration amendment issued.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to issue amendment.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <form
        onSubmit={(e) => void handleSubmit(e)}
        className="flex max-h-[90vh] w-full max-w-lg flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">Issue Amendment</h2>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel htmlFor="amend-title" required>
              Title
            </FieldLabel>
            <input
              id="amend-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          <div>
            <FieldLabel htmlFor="amend-reason" required>
              Reason
            </FieldLabel>
            <textarea
              id="amend-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          <div>
            <FieldLabel htmlFor="amend-guidance">Public guidance</FieldLabel>
            <textarea
              id="amend-guidance"
              value={publicGuidance}
              onChange={(e) => setPublicGuidance(e.target.value)}
              rows={2}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          <div>
            <FieldLabel htmlFor="amend-legal">Legal reference</FieldLabel>
            <input
              id="amend-legal"
              value={legalReference}
              onChange={(e) => setLegalReference(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" isLoading={isSubmitting} disabled={isSubmitting}>
            Issue amendment
          </Button>
        </div>
      </form>
    </div>
  );
}
