"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postAgencyShelterOccupancy } from "@/lib/agency-disaster-api";
import type { DisasterShelterActivation } from "@/types/disaster-operations";

type AgencyShelterOccupancyModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  shelter: DisasterShelterActivation | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AgencyShelterOccupancyModal({
  open,
  disasterPublicUuid,
  shelter,
  onClose,
  onSuccess,
}: AgencyShelterOccupancyModalProps) {
  const [peopleCount, setPeopleCount] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPeopleCount(
      shelter?.latest_occupancy != null ? String(shelter.latest_occupancy) : "",
    );
    setSubmitError(null);
  }, [open, shelter]);

  if (!open || !shelter?.shelter_activation_public_uuid) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const count = Number(peopleCount);
    if (!Number.isFinite(count) || count < 0) {
      setSubmitError("Enter a valid non-negative people count.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postAgencyShelterOccupancy(
        disasterPublicUuid,
        shelter.shelter_activation_public_uuid!,
        { peopleCount: count },
      );
      toast.success("Occupancy recorded.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to record occupancy.",
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
          <h2 className="text-lg font-semibold text-slate-900">Record Occupancy</h2>
          <p className="mt-1 text-sm text-slate-600">{shelter.facility_name}</p>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="agency-people-count" required>
              People count
            </FieldLabel>
            <input
              id="agency-people-count"
              type="number"
              min={0}
              value={peopleCount}
              onChange={(e) => setPeopleCount(e.target.value)}
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
            Save
          </Button>
        </div>
      </form>
    </div>
  );
}
