"use client";

import { type FormEvent, useEffect, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { addAgencyRepresentative } from "@/lib/admin-agency-api";
import { UUID_PATTERN } from "@/lib/admin-role-errors";

type AddRepresentativeDialogProps = {
  open: boolean;
  agencyPublicUuid: string | null;
  agencyName?: string;
  onClose: () => void;
  onSuccess: () => void;
};

export function AddRepresentativeDialog({
  open,
  agencyPublicUuid,
  agencyName,
  onClose,
  onSuccess,
}: AddRepresentativeDialogProps) {
  const [userPublicUuid, setUserPublicUuid] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setUserPublicUuid("");
    setFieldError(null);
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!agencyPublicUuid) return;

    const trimmed = userPublicUuid.trim();
    if (!trimmed) {
      setFieldError("User public UUID is required.");
      return;
    }
    if (!UUID_PATTERN.test(trimmed)) {
      setFieldError("Enter a valid user public UUID.");
      return;
    }

    setFieldError(null);
    setSubmitError(null);
    setIsSubmitting(true);

    try {
      await addAgencyRepresentative(agencyPublicUuid, trimmed);
      onClose();
      onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not add representative.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open || !agencyPublicUuid) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4">
      <form
        className="flex w-full max-w-md flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="add-rep-title"
        aria-modal="true"
        onSubmit={(event) => void handleSubmit(event)}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="add-rep-title"
            className="text-lg font-semibold text-slate-900"
          >
            Add representative
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            {agencyName
              ? `Link a user to ${agencyName}.`
              : "Link a user as an agency representative."}{" "}
            Provide the user public UUID.
          </p>
        </div>

        <div className="space-y-4 px-5 py-4">
          {submitError ? <ErrorAlert message={submitError} /> : null}
          <div>
            <FieldLabel htmlFor="add-rep-user-uuid" required>
              User public UUID
            </FieldLabel>
            <input
              id="add-rep-user-uuid"
              type="text"
              value={userPublicUuid}
              onChange={(e) => setUserPublicUuid(e.target.value)}
              className={triageFieldClassName}
              autoComplete="off"
              required
            />
            {fieldError ? (
              <p className="mt-1 text-xs text-red-600">{fieldError}</p>
            ) : null}
          </div>
        </div>

        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={handleClose}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button type="submit" size="sm" isLoading={isSubmitting}>
            Add representative
          </Button>
        </div>
      </form>
    </div>
  );
}
