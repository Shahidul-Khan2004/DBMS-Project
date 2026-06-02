"use client";

import { type FormEvent, useEffect, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { updateAdminAgency } from "@/lib/admin-agency-api";
import type { AdminAgencyListItem } from "@/types/admin-agency";

type EditAgencyDialogProps = {
  open: boolean;
  agency: AdminAgencyListItem | null;
  onClose: () => void;
  onSuccess: () => void;
};

export function EditAgencyDialog({
  open,
  agency,
  onClose,
  onSuccess,
}: EditAgencyDialogProps) {
  const [agencyCode, setAgencyCode] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open || !agency) return;
    setAgencyCode(agency.agency_code);
    setName(agency.name);
    setDescription(agency.description ?? "");
    setFieldErrors({});
    setSubmitError(null);
  }, [open, agency]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!agency) return;

    const errors: Record<string, string> = {};
    if (!agencyCode.trim()) errors.agencyCode = "Agency code is required.";
    if (!name.trim()) errors.name = "Agency name is required.";
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setFieldErrors({});
    setSubmitError(null);
    setIsSubmitting(true);

    try {
      await updateAdminAgency(agency.public_uuid, {
        agency_code: agencyCode.trim(),
        name: name.trim(),
        description: description.trim() || undefined,
      });
      onClose();
      onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not update agency.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open || !agency) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4">
      <form
        className="flex w-full max-w-lg flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="edit-agency-title"
        aria-modal="true"
        onSubmit={(event) => void handleSubmit(event)}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="edit-agency-title"
            className="text-lg font-semibold text-slate-900"
          >
            Edit agency
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Update agency metadata. Activation status is changed separately.
          </p>
        </div>

        <div className="space-y-4 px-5 py-4">
          {submitError ? <ErrorAlert message={submitError} /> : null}
          <div>
            <FieldLabel htmlFor="edit-agency-code" required>
              Agency code
            </FieldLabel>
            <input
              id="edit-agency-code"
              type="text"
              value={agencyCode}
              onChange={(e) => setAgencyCode(e.target.value)}
              className={triageFieldClassName}
              required
            />
            {fieldErrors.agencyCode ? (
              <p className="mt-1 text-xs text-red-600">{fieldErrors.agencyCode}</p>
            ) : null}
          </div>
          <div>
            <FieldLabel htmlFor="edit-agency-name" required>
              Agency name
            </FieldLabel>
            <input
              id="edit-agency-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={triageFieldClassName}
              required
            />
            {fieldErrors.name ? (
              <p className="mt-1 text-xs text-red-600">{fieldErrors.name}</p>
            ) : null}
          </div>
          <div>
            <FieldLabel htmlFor="edit-agency-description">Description</FieldLabel>
            <textarea
              id="edit-agency-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className={triageFieldClassName}
              rows={3}
            />
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
            Save changes
          </Button>
        </div>
      </form>
    </div>
  );
}
