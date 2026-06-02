"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { updateAgencyUnitStatus } from "@/lib/agency-api";
import { mapAgencyUnitStatusError } from "@/lib/agency-api-errors";
import type { AgencyUnit, AgencyUnitStatusCode } from "@/types/agency";

type AgencyUnitStatusModalProps = {
  open: boolean;
  unit: AgencyUnit | null;
  targetStatus: AgencyUnitStatusCode | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AgencyUnitStatusModal({
  open,
  unit,
  targetStatus,
  onClose,
  onSuccess,
}: AgencyUnitStatusModalProps) {
  const [note, setNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setNote("");
    setSubmitError(null);
  }, [open, unit?.public_uuid, targetStatus]);

  if (!open || !unit || !targetStatus) return null;

  const title =
    targetStatus === "available" ? "Set unit as available?" : "Set unit as busy?";

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await updateAgencyUnitStatus(unit.public_uuid, {
        status_code: targetStatus,
        note: note.trim() || undefined,
      });
      toast.success(
        targetStatus === "available"
          ? "Unit marked as available."
          : "Unit marked as busy.",
      );
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(mapAgencyUnitStatusError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex w-full max-w-md flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
          <p className="mt-1 text-sm text-slate-600">
            {unit.unit_name} · {unit.unit_code}
          </p>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="agency-unit-status-note">Note</FieldLabel>
            <textarea
              id="agency-unit-status-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              rows={2}
              className={triageFieldClassName}
              placeholder="Optional context"
            />
          </div>
          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
          >
            Confirm
          </Button>
        </div>
      </div>
    </div>
  );
}
