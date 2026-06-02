"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { deactivateAgencyUnit } from "@/lib/agency-api";
import { mapAgencyDeactivateUnitError } from "@/lib/agency-api-errors";
import type { AgencyUnit } from "@/types/agency";

type AgencyDeactivateUnitModalProps = {
  open: boolean;
  unit: AgencyUnit | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AgencyDeactivateUnitModal({
  open,
  unit,
  onClose,
  onSuccess,
}: AgencyDeactivateUnitModalProps) {
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!open || !unit) return null;

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await deactivateAgencyUnit(unit.public_uuid);
      toast.success("Unit deactivated.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(mapAgencyDeactivateUnitError(err));
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
          <h2 className="text-lg font-semibold text-slate-900">Deactivate unit?</h2>
          <p className="mt-1 text-sm text-slate-600">
            {unit.unit_name} · {unit.unit_code}
          </p>
        </div>
        <div className="px-5 py-4">
          <p className="text-sm text-slate-700">
            This unit will no longer be available for dispatch until reactivated by an
            administrator.
          </p>
          {submitError ? <div className="mt-3"><ErrorAlert message={submitError} /></div> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="danger"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
          >
            Deactivate
          </Button>
        </div>
      </div>
    </div>
  );
}
