"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { createAgencyIncidentResponseLog } from "@/lib/agency-api";
import { mapAgencyResponseLogError } from "@/lib/agency-api-errors";
import type { AgencyDispatch, AgencyResponseLogType } from "@/types/agency";

const LOG_TYPE_OPTIONS: Array<{ value: AgencyResponseLogType; label: string }> = [
  { value: "update", label: "Update" },
  { value: "hazard", label: "Hazard" },
  { value: "casualty", label: "Casualty" },
  { value: "resource_need", label: "Resource Need" },
  { value: "completion_note", label: "Completion Note" },
];

type AgencyAddResponseLogModalProps = {
  open: boolean;
  incidentPublicUuid: string | null;
  defaultDispatch: AgencyDispatch | null;
  relatedDispatches: AgencyDispatch[];
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AgencyAddResponseLogModal({
  open,
  incidentPublicUuid,
  defaultDispatch,
  relatedDispatches,
  onClose,
  onSuccess,
}: AgencyAddResponseLogModalProps) {
  const [logType, setLogType] = useState<AgencyResponseLogType>("update");
  const [message, setMessage] = useState("");
  const [dispatchUuid, setDispatchUuid] = useState<string>("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLogType("update");
    setMessage("");
    setDispatchUuid(defaultDispatch?.public_uuid ?? "");
    setSubmitError(null);
  }, [open, defaultDispatch?.public_uuid]);

  const canSubmit = Boolean(incidentPublicUuid && message.trim());

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    if (!incidentPublicUuid || !canSubmit) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await createAgencyIncidentResponseLog(incidentPublicUuid, {
        log_type: logType,
        message: message.trim(),
        dispatch_public_uuid: dispatchUuid.trim() || undefined,
      });
      toast.success("Field update recorded.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(mapAgencyResponseLogError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open || !incidentPublicUuid) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex max-h-[90vh] w-full max-w-md flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="agency-add-response-log-title"
        aria-modal="true"
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="agency-add-response-log-title"
            className="text-lg font-semibold text-slate-900"
          >
            Add Field Update
          </h2>
        </div>

        <div className="space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel htmlFor="agency-log-type" required>
              Log Type
            </FieldLabel>
            <select
              id="agency-log-type"
              value={logType}
              onChange={(event) =>
                setLogType(event.target.value as AgencyResponseLogType)
              }
              className={triageFieldClassName}
            >
              {LOG_TYPE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <FieldLabel htmlFor="agency-log-message" required>
              Message
            </FieldLabel>
            <textarea
              id="agency-log-message"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              rows={4}
              className={triageFieldClassName}
              placeholder="Describe field conditions, actions taken, or resource needs"
            />
          </div>

          {relatedDispatches.length > 0 ? (
            <div>
              <FieldLabel htmlFor="agency-log-dispatch">Related Dispatch</FieldLabel>
              <select
                id="agency-log-dispatch"
                value={dispatchUuid}
                onChange={(event) => setDispatchUuid(event.target.value)}
                className={triageFieldClassName}
              >
                <option value="">None</option>
                {relatedDispatches.map((dispatch) => (
                  <option key={dispatch.public_uuid} value={dispatch.public_uuid}>
                    {dispatch.unit.unit_code} · {dispatch.incident.incident_code} ·{" "}
                    {dispatch.status_code}
                  </option>
                ))}
              </select>
            </div>
          ) : null}

          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>

        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button
            type="button"
            variant="secondary"
            onClick={handleClose}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={!canSubmit || isSubmitting}
          >
            Save Update
          </Button>
        </div>
      </div>
    </div>
  );
}
