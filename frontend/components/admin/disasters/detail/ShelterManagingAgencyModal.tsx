"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { DisasterAgencyPicker } from "@/components/admin/disasters/detail/DisasterAgencyPicker";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postShelterManagingAgency } from "@/lib/disaster-operations-api";
import type { DisasterShelterActivation } from "@/types/disaster-operations";

type ShelterManagingAgencyModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  shelter: DisasterShelterActivation | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function ShelterManagingAgencyModal({
  open,
  disasterPublicUuid,
  shelter,
  onClose,
  onSuccess,
}: ShelterManagingAgencyModalProps) {
  const [agencyPublicUuid, setAgencyPublicUuid] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setAgencyPublicUuid("");
    setSubmitError(null);
  }, [open]);

  if (!open || !shelter?.shelter_activation_public_uuid) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!agencyPublicUuid) {
      setSubmitError("Select an agency.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postShelterManagingAgency(
        disasterPublicUuid,
        shelter.shelter_activation_public_uuid!,
        { agencyPublicUuid },
      );
      toast.success("Managing agency assigned.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to assign managing agency.",
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
          <h2 className="text-lg font-semibold text-slate-900">Assign Managing Agency</h2>
          <p className="mt-1 text-sm text-slate-600">{shelter.facility_name}</p>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <FieldLabel required>Agency</FieldLabel>
          <DisasterAgencyPicker
            selectedAgencyPublicUuid={agencyPublicUuid}
            onSelect={setAgencyPublicUuid}
            disabled={isSubmitting}
          />
          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" isLoading={isSubmitting} disabled={isSubmitting}>
            Assign
          </Button>
        </div>
      </form>
    </div>
  );
}
