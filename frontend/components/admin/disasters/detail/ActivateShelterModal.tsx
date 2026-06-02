"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { DisasterFacilityPicker } from "@/components/admin/disasters/detail/DisasterFacilityPicker";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postActivateDisasterShelter } from "@/lib/disaster-operations-api";

type ActivateShelterModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function ActivateShelterModal({
  open,
  disasterPublicUuid,
  onClose,
  onSuccess,
}: ActivateShelterModalProps) {
  const [facilityPublicUuid, setFacilityPublicUuid] = useState("");
  const [manualOverrideNote, setManualOverrideNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setFacilityPublicUuid("");
    setManualOverrideNote("");
    setSubmitError(null);
  }, [open]);

  if (!open) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!facilityPublicUuid) {
      setSubmitError("Select a facility.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postActivateDisasterShelter(disasterPublicUuid, {
        facilityPublicUuid,
        manualOverrideNote: manualOverrideNote.trim() || undefined,
      });
      toast.success("Shelter activated.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to activate shelter.",
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
          <h2 className="text-lg font-semibold text-slate-900">Activate Shelter</h2>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <DisasterFacilityPicker
            mode="shelter"
            selectedFacilityPublicUuid={facilityPublicUuid}
            onSelect={setFacilityPublicUuid}
            disabled={isSubmitting}
          />
          <div>
            <FieldLabel htmlFor="shelter-override-note">
              Manual override note
            </FieldLabel>
            <textarea
              id="shelter-override-note"
              value={manualOverrideNote}
              onChange={(e) => setManualOverrideNote(e.target.value)}
              placeholder="Required if facility is outside affected areas"
              rows={2}
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
            Activate
          </Button>
        </div>
      </form>
    </div>
  );
}
