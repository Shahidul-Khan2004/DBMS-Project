"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { deleteUnlinkDisasterIncident } from "@/lib/disaster-operations-api";
import type { DisasterLinkedIncident } from "@/types/disaster-operations";

type UnlinkIncidentModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  incident: DisasterLinkedIncident | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function UnlinkIncidentModal({
  open,
  disasterPublicUuid,
  incident,
  onClose,
  onSuccess,
}: UnlinkIncidentModalProps) {
  const [reason, setReason] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setReason("");
    setSubmitError(null);
  }, [open]);

  if (!open || !incident) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = reason.trim();
    if (!trimmed) {
      setSubmitError("Reason is required.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await deleteUnlinkDisasterIncident(
        disasterPublicUuid,
        incident.incident_public_uuid,
        { reason: trimmed },
      );
      toast.success("Incident unlinked.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to unlink incident.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <form
        onSubmit={(e) => void handleSubmit(e)}
        className="flex w-full max-w-md flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">Unlink Incident</h2>
          <p className="mt-1 text-sm text-slate-600">
            {incident.title ?? "Incident"} · {incident.incident_code}
          </p>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="unlink-reason" required>
              Reason
            </FieldLabel>
            <textarea
              id="unlink-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              maxLength={500}
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
          <Button type="submit" variant="danger" isLoading={isSubmitting} disabled={isSubmitting}>
            Unlink
          </Button>
        </div>
      </form>
    </div>
  );
}
