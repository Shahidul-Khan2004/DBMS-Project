"use client";

import { type FormEvent, useEffect, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { activateDisasterShelter } from "@/components/admin/disasters/detail/disasterFacilityActivation";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";

type ActivateShelterModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  facilityPublicUuid: string;
  facilityLabel: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function ActivateShelterModal({
  open,
  disasterPublicUuid,
  facilityPublicUuid,
  facilityLabel,
  onClose,
  onSuccess,
}: ActivateShelterModalProps) {
  const [manualOverrideNote, setManualOverrideNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setManualOverrideNote("");
    setSubmitError(null);
  }, [open, facilityPublicUuid]);

  if (!open || !facilityPublicUuid) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const note = manualOverrideNote.trim();
    if (!note) {
      setSubmitError("Enter a reason for activating this facility outside affected areas.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const result = await activateDisasterShelter(disasterPublicUuid, {
        facilityPublicUuid,
        manualOverrideNote: note,
      });
      if (!result.ok) {
        setSubmitError(result.error);
        if (result.alreadyActive) {
          await onSuccess();
        }
        return;
      }
      onClose();
      await onSuccess();
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
          <h2 className="text-lg font-semibold text-slate-900">Manual shelter override</h2>
          <p className="mt-2 text-sm font-medium text-slate-900">{facilityLabel}</p>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel htmlFor="shelter-override-note" required>
              Reason for activation outside affected areas
            </FieldLabel>
            <textarea
              id="shelter-override-note"
              value={manualOverrideNote}
              onChange={(e) => setManualOverrideNote(e.target.value)}
              rows={4}
              maxLength={1000}
              disabled={isSubmitting}
              placeholder="Explain why this shelter must be activated despite being outside affected areas."
              className={`${triageFieldClassName} mt-1 min-h-[6rem] resize-y`}
            />
          </div>
          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            type="submit"
            isLoading={isSubmitting}
            disabled={isSubmitting || !manualOverrideNote.trim()}
          >
            Activate with override
          </Button>
        </div>
      </form>
    </div>
  );
}
