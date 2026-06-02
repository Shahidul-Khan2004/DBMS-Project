"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { DisasterAgencyPicker } from "@/components/admin/disasters/detail/DisasterAgencyPicker";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postDisasterResponsibility } from "@/lib/disaster-operations-api";
import { DISASTER_RESPONSIBILITY_TYPE_OPTIONS } from "@/lib/disaster-operations-format";

type AssignResponsibilityModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AssignResponsibilityModal({
  open,
  disasterPublicUuid,
  onClose,
  onSuccess,
}: AssignResponsibilityModalProps) {
  const [agencyPublicUuid, setAgencyPublicUuid] = useState("");
  const [responsibilityType, setResponsibilityType] = useState("coordination");
  const [isLead, setIsLead] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setAgencyPublicUuid("");
    setResponsibilityType("coordination");
    setIsLead(false);
    setSubmitError(null);
  }, [open]);

  if (!open) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!agencyPublicUuid) {
      setSubmitError("Select an agency.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postDisasterResponsibility(disasterPublicUuid, {
        agencyPublicUuid,
        responsibilityType:
          responsibilityType as (typeof DISASTER_RESPONSIBILITY_TYPE_OPTIONS)[number]["value"],
        isLead,
      });
      toast.success("Responsibility assigned.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to assign responsibility.",
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
          <h2 className="text-lg font-semibold text-slate-900">Assign Responsibility</h2>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel required>Agency</FieldLabel>
            <DisasterAgencyPicker
              selectedAgencyPublicUuid={agencyPublicUuid}
              onSelect={setAgencyPublicUuid}
              disabled={isSubmitting}
            />
          </div>
          <div>
            <FieldLabel htmlFor="responsibility-type" required>
              Responsibility type
            </FieldLabel>
            <select
              id="responsibility-type"
              value={responsibilityType}
              onChange={(e) => setResponsibilityType(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            >
              {DISASTER_RESPONSIBILITY_TYPE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={isLead}
              onChange={(e) => setIsLead(e.target.checked)}
              disabled={isSubmitting}
            />
            Lead agency for this type
          </label>
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
