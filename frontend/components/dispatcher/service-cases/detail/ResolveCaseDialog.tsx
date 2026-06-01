"use client";

import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { postOperationsServiceCaseResolve } from "@/lib/service-case-api";
import type { ServiceCaseResolutionType } from "@/types/service-case";

const RESOLUTION_OPTIONS: { value: ServiceCaseResolutionType; label: string }[] =
  [
    { value: "advice_given", label: "Advice Given" },
    { value: "referred_to_facility", label: "Referred to Facility" },
    { value: "no_action_needed", label: "No Action Needed" },
    { value: "duplicate", label: "Duplicate" },
  ];

type ResolveCaseDialogProps = {
  open: boolean;
  casePublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function ResolveCaseDialog({
  open,
  casePublicUuid,
  onClose,
  onSuccess,
}: ResolveCaseDialogProps) {
  const [resolutionType, setResolutionType] =
    useState<ServiceCaseResolutionType>("advice_given");
  const [resolutionText, setResolutionText] = useState("");
  const [narrativeError, setNarrativeError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setResolutionType("advice_given");
    setResolutionText("");
    setNarrativeError(null);
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (isSubmitting) return;

    const trimmed = resolutionText.trim();
    if (!trimmed) {
      setNarrativeError("Resolution narrative is required.");
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);
    setNarrativeError(null);

    try {
      await postOperationsServiceCaseResolve(casePublicUuid, {
        resolutionType,
        resolutionText: trimmed,
      });
      toast.success("Service case resolved.");
      onClose();
      await onSuccess();
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not resolve service case.";
      setSubmitError(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex w-full max-w-lg flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="resolve-case-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="resolve-case-title"
            className="text-lg font-semibold text-slate-900"
          >
            Resolve Case
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Record how this service case was resolved.
          </p>
        </div>

        <form onSubmit={(event) => void handleSubmit(event)} className="flex flex-col">
          <div className="space-y-4 px-5 py-4">
            {submitError ? <ErrorAlert message={submitError} /> : null}
            <div>
              <FieldLabel htmlFor="resolution-type">Resolution type</FieldLabel>
              <select
                id="resolution-type"
                value={resolutionType}
                onChange={(event) =>
                  setResolutionType(event.target.value as ServiceCaseResolutionType)
                }
                className={triageFieldClassName}
                disabled={isSubmitting}
              >
                {RESOLUTION_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <FieldLabel htmlFor="resolution-text" required>
                Resolution narrative
              </FieldLabel>
              <textarea
                id="resolution-text"
                value={resolutionText}
                onChange={(event) => setResolutionText(event.target.value)}
                className={triageFieldClassName}
                rows={5}
                required
                disabled={isSubmitting}
              />
              {narrativeError ? (
                <p className="mt-1 text-xs text-red-600">{narrativeError}</p>
              ) : null}
            </div>
          </div>

          <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={handleClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              isLoading={isSubmitting}
              disabled={isSubmitting}
            >
              Resolve Case
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
