"use client";

import { type FormEvent, useEffect, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { linkAgencyRepresentative } from "@/lib/admin-agency-api";
import {
  formatAdminAgencyError,
  UUID_PATTERN,
} from "@/lib/admin-agency-errors";
import { toast } from "sonner";

type AddRepresentativeDialogProps = {
  open: boolean;
  agencyPublicUuid: string | null;
  agencyName?: string;
  agencyCode?: string;
  onClose: () => void;
  onSuccess: () => void;
};

export function AddRepresentativeDialog({
  open,
  agencyPublicUuid,
  agencyName,
  agencyCode,
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

  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !isSubmitting) {
        onClose();
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, isSubmitting, onClose]);

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
      await linkAgencyRepresentative(agencyPublicUuid, trimmed);
      toast.success("Agency representative linked.");
      onClose();
      onSuccess();
    } catch (err) {
      setSubmitError(formatAdminAgencyError(err));
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
            Link agency representative
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Link an existing user to this agency as a representative.
          </p>
        </div>

        <div className="space-y-4 px-5 py-4">
          {submitError ? <ErrorAlert message={submitError} /> : null}

          <dl className="space-y-2 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5 text-sm">
            <div>
              <dt className="text-xs text-slate-500">Agency name</dt>
              <dd className="mt-0.5 font-medium text-slate-900">
                {agencyName ?? "Selected agency"}
              </dd>
            </div>
            {agencyCode ? (
              <div>
                <dt className="text-xs text-slate-500">Agency code</dt>
                <dd className="mt-0.5 text-slate-900">{agencyCode}</dd>
              </div>
            ) : null}
          </dl>

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
              disabled={isSubmitting}
            />
            <p className="mt-1 text-xs text-slate-500">
              Enter the existing user public UUID. User search is not available
              in the current API.
            </p>
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
            Link representative
          </Button>
        </div>
      </form>
    </div>
  );
}
