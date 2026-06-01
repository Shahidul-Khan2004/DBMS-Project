"use client";

import { type FormEvent, useEffect, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { onboardAgency } from "@/lib/admin-agency-api";
import { ADMIN_AGENCY_TYPE_OPTIONS } from "@/lib/admin-agency-types";
import { UUID_PATTERN } from "@/lib/admin-role-errors";

type OnboardMode = "existing" | "new";

type OnboardAgencyDialogProps = {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
};

export function OnboardAgencyDialog({
  open,
  onClose,
  onSuccess,
}: OnboardAgencyDialogProps) {
  const [mode, setMode] = useState<OnboardMode>("existing");
  const [userPublicUuid, setUserPublicUuid] = useState("");
  const [agencyPublicUuid, setAgencyPublicUuid] = useState("");
  const [agencyCode, setAgencyCode] = useState("");
  const [agencyName, setAgencyName] = useState("");
  const [agencyTypeCode, setAgencyTypeCode] = useState<string>(
    ADMIN_AGENCY_TYPE_OPTIONS[0].value,
  );
  const [description, setDescription] = useState("");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setMode("existing");
    setUserPublicUuid("");
    setAgencyPublicUuid("");
    setAgencyCode("");
    setAgencyName("");
    setAgencyTypeCode(ADMIN_AGENCY_TYPE_OPTIONS[0].value);
    setDescription("");
    setFieldErrors({});
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const errors: Record<string, string> = {};
    const trimmedUser = userPublicUuid.trim();

    if (!trimmedUser) {
      errors.userPublicUuid = "User public UUID is required.";
    } else if (!UUID_PATTERN.test(trimmedUser)) {
      errors.userPublicUuid = "Enter a valid user public UUID.";
    }

    if (mode === "existing") {
      const trimmedAgency = agencyPublicUuid.trim();
      if (!trimmedAgency) {
        errors.agencyPublicUuid = "Agency public UUID is required.";
      } else if (!UUID_PATTERN.test(trimmedAgency)) {
        errors.agencyPublicUuid = "Enter a valid agency public UUID.";
      }
    } else {
      if (!agencyCode.trim()) errors.agencyCode = "Agency code is required.";
      if (!agencyName.trim()) errors.agencyName = "Agency name is required.";
      if (!agencyTypeCode.trim()) {
        errors.agencyTypeCode = "Agency type is required.";
      }
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setFieldErrors({});
    setSubmitError(null);
    setIsSubmitting(true);

    try {
      if (mode === "existing") {
        await onboardAgency({
          user_public_uuid: trimmedUser,
          agency_public_uuid: agencyPublicUuid.trim(),
        });
      } else {
        await onboardAgency({
          user_public_uuid: trimmedUser,
          agency: {
            agency_code: agencyCode.trim(),
            name: agencyName.trim(),
            agency_type_code: agencyTypeCode,
            ...(description.trim()
              ? { description: description.trim() }
              : {}),
          },
        });
      }
      onClose();
      onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not onboard agency representative.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4">
      <form
        className="flex w-full max-w-lg max-h-[90vh] flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="onboard-agency-title"
        aria-modal="true"
        onSubmit={(event) => void handleSubmit(event)}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="onboard-agency-title"
            className="text-lg font-semibold text-slate-900"
          >
            Onboard agency representative
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Link a user as an agency representative. The backend requires the
            user public UUID; there is no user search API.
          </p>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {submitError ? <ErrorAlert message={submitError} /> : null}

          <fieldset className="space-y-2">
            <legend className="text-sm font-semibold text-slate-700">
              Agency mode
            </legend>
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="radio"
                name="onboard-mode"
                checked={mode === "existing"}
                onChange={() => setMode("existing")}
              />
              Existing agency
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="radio"
                name="onboard-mode"
                checked={mode === "new"}
                onChange={() => setMode("new")}
              />
              New agency
            </label>
          </fieldset>

          <div>
            <FieldLabel htmlFor="onboard-user-uuid" required>
              User public UUID
            </FieldLabel>
            <input
              id="onboard-user-uuid"
              type="text"
              value={userPublicUuid}
              onChange={(e) => setUserPublicUuid(e.target.value)}
              className={triageFieldClassName}
              autoComplete="off"
              required
            />
            {fieldErrors.userPublicUuid ? (
              <p className="mt-1 text-xs text-red-600">
                {fieldErrors.userPublicUuid}
              </p>
            ) : null}
          </div>

          {mode === "existing" ? (
            <div>
              <FieldLabel htmlFor="onboard-agency-uuid" required>
                Agency public UUID
              </FieldLabel>
              <input
                id="onboard-agency-uuid"
                type="text"
                value={agencyPublicUuid}
                onChange={(e) => setAgencyPublicUuid(e.target.value)}
                className={triageFieldClassName}
                autoComplete="off"
                required
              />
              {fieldErrors.agencyPublicUuid ? (
                <p className="mt-1 text-xs text-red-600">
                  {fieldErrors.agencyPublicUuid}
                </p>
              ) : null}
            </div>
          ) : (
            <>
              <div>
                <FieldLabel htmlFor="onboard-agency-code" required>
                  Agency code
                </FieldLabel>
                <input
                  id="onboard-agency-code"
                  type="text"
                  value={agencyCode}
                  onChange={(e) => setAgencyCode(e.target.value)}
                  className={triageFieldClassName}
                  required
                />
                {fieldErrors.agencyCode ? (
                  <p className="mt-1 text-xs text-red-600">
                    {fieldErrors.agencyCode}
                  </p>
                ) : null}
              </div>
              <div>
                <FieldLabel htmlFor="onboard-agency-name" required>
                  Agency name
                </FieldLabel>
                <input
                  id="onboard-agency-name"
                  type="text"
                  value={agencyName}
                  onChange={(e) => setAgencyName(e.target.value)}
                  className={triageFieldClassName}
                  required
                />
                {fieldErrors.agencyName ? (
                  <p className="mt-1 text-xs text-red-600">
                    {fieldErrors.agencyName}
                  </p>
                ) : null}
              </div>
              <div>
                <FieldLabel htmlFor="onboard-agency-type" required>
                  Agency type
                </FieldLabel>
                <select
                  id="onboard-agency-type"
                  value={agencyTypeCode}
                  onChange={(e) => setAgencyTypeCode(e.target.value)}
                  className={triageFieldClassName}
                  required
                >
                  {ADMIN_AGENCY_TYPE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <FieldLabel htmlFor="onboard-description">Description</FieldLabel>
                <textarea
                  id="onboard-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className={triageFieldClassName}
                  rows={2}
                />
              </div>
            </>
          )}
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
            Onboard
          </Button>
        </div>
      </form>
    </div>
  );
}
