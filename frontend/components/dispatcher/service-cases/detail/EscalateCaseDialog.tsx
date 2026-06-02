"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { postIntakeReportEscalate } from "@/lib/service-case-api";
import type { IntakeEscalatePayload } from "@/types/service-case";

type EscalateCaseDialogProps = {
  open: boolean;
  intakePublicUuid: string;
  defaultTitle?: string;
  onClose: () => void;
  onSuccess: (incidentPublicUuid: string | null) => Promise<void>;
};

export function EscalateCaseDialog({
  open,
  intakePublicUuid,
  defaultTitle = "",
  onClose,
  onSuccess,
}: EscalateCaseDialogProps) {
  const [severityCode, setSeverityCode] =
    useState<IntakeEscalatePayload["severityCode"]>("medium");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [escalationReason, setEscalationReason] = useState("");
  const [reasonError, setReasonError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setSeverityCode("medium");
    setIncidentTitle(defaultTitle);
    setIncidentDescription("");
    setEscalationReason("");
    setReasonError(null);
    setSubmitError(null);
  }, [open, defaultTitle]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    const trimmedReason = escalationReason.trim();
    if (!trimmedReason) {
      setReasonError("Escalation reason is required.");
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);
    setReasonError(null);

    try {
      const data = await postIntakeReportEscalate(intakePublicUuid, {
        severityCode,
        escalationReason: trimmedReason,
        incidentTitle: incidentTitle.trim() || undefined,
        incidentDescription: incidentDescription.trim() || undefined,
      });
      toast.success(
        data.message ?? "Service case escalated to emergency incident.",
      );
      const incidentPublicUuid = data.incident?.public_uuid ?? null;
      onClose();
      await onSuccess(incidentPublicUuid);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not escalate service case.";
      setSubmitError(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex w-full max-w-lg max-h-[90vh] flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="escalate-case-title"
        aria-modal="true"
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="escalate-case-title"
            className="text-lg font-semibold text-slate-900"
          >
            Escalate to Emergency
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Create an emergency incident from this service case&apos;s intake
            report.
          </p>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {submitError ? <ErrorAlert message={submitError} /> : null}
          <div>
            <FieldLabel htmlFor="escalate-severity">Severity</FieldLabel>
            <select
              id="escalate-severity"
              value={severityCode}
              onChange={(event) =>
                setSeverityCode(
                  event.target.value as IntakeEscalatePayload["severityCode"],
                )
              }
              className={triageFieldClassName}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div>
            <FieldLabel htmlFor="escalate-reason" required>
              Escalation reason
            </FieldLabel>
            <textarea
              id="escalate-reason"
              value={escalationReason}
              onChange={(event) => setEscalationReason(event.target.value)}
              className={triageFieldClassName}
              rows={3}
              maxLength={1000}
              required
            />
            {reasonError ? (
              <p className="mt-1 text-xs text-red-600">{reasonError}</p>
            ) : null}
          </div>
          <div>
            <FieldLabel htmlFor="escalate-incident-title">Incident title</FieldLabel>
            <input
              id="escalate-incident-title"
              type="text"
              value={incidentTitle}
              onChange={(event) => setIncidentTitle(event.target.value)}
              className={triageFieldClassName}
              maxLength={255}
            />
          </div>
          <div>
            <FieldLabel htmlFor="escalate-incident-description">
              Incident description
            </FieldLabel>
            <textarea
              id="escalate-incident-description"
              value={incidentDescription}
              onChange={(event) => setIncidentDescription(event.target.value)}
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
          <Button
            type="button"
            size="sm"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
          >
            Escalate to Emergency
          </Button>
        </div>
      </div>
    </div>
  );
}
