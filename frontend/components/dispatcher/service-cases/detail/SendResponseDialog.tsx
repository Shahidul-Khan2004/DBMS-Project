"use client";

import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { canSendDispatcherCitizenMessage } from "@/components/dispatcher/service-cases/detail/serviceCaseActions";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { postOperationsServiceCaseMessage } from "@/lib/service-case-api";
import type { DispatcherServiceCaseMessageType } from "@/types/service-case";

const MESSAGE_TYPE_OPTIONS: {
  value: DispatcherServiceCaseMessageType;
  label: string;
  helper: string;
}[] = [
  {
    value: "admin_reply",
    label: "Official response",
    helper: "Sent to the citizen and shown in their conversation thread.",
  },
  {
    value: "system_note",
    label: "Internal note",
    helper: "Visible only to the operations team. Not shared with the citizen.",
  },
];

type SendResponseDialogProps = {
  open: boolean;
  casePublicUuid: string;
  statusCode: string | null | undefined;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

function getSendMessageCopy(
  statusCode: string | null | undefined,
  messageType: DispatcherServiceCaseMessageType,
) {
  const isInternal = messageType === "system_note";
  const isFollowUp = !isInternal && statusCode === "awaiting_user_response";

  return {
    title: isInternal
      ? "Add Internal Note"
      : isFollowUp
        ? "Send Follow-up"
        : "Send Response",
    submitLabel: isInternal
      ? "Save Internal Note"
      : isFollowUp
        ? "Send Follow-up"
        : "Send Response",
    successToast: isInternal
      ? "Internal note saved."
      : isFollowUp
        ? "Follow-up sent to the reporter."
        : "Response sent to the reporter.",
    errorFallback: isInternal
      ? "Could not save internal note."
      : isFollowUp
        ? "Could not send follow-up."
        : "Could not send response.",
    showUnderReviewHelper:
      !isInternal && statusCode === "under_review",
    dialogDescription: isInternal
      ? "Record an internal note for the operations team."
      : "Reply to the reporter on this service case.",
  };
}

export function SendResponseDialog({
  open,
  casePublicUuid,
  statusCode,
  onClose,
  onSuccess,
}: SendResponseDialogProps) {
  const [messageType, setMessageType] =
    useState<DispatcherServiceCaseMessageType>("admin_reply");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [subjectError, setSubjectError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const copy = getSendMessageCopy(statusCode, messageType);
  const selectedTypeOption =
    MESSAGE_TYPE_OPTIONS.find((option) => option.value === messageType) ??
    MESSAGE_TYPE_OPTIONS[0];
  const canSend = canSendDispatcherCitizenMessage(statusCode);

  useEffect(() => {
    if (!open) return;
    setMessageType("admin_reply");
    setSubject("");
    setMessage("");
    setSubjectError(null);
    setSubmitError(null);
  }, [open]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (isSubmitting) return;

    if (!canSend) {
      setSubmitError(
        "Start reviewing this case before sending an official response.",
      );
      return;
    }

    const trimmedSubject = subject.trim();
    if (!trimmedSubject) {
      setSubjectError("Subject is required.");
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);
    setSubjectError(null);

    try {
      await postOperationsServiceCaseMessage(casePublicUuid, {
        title: trimmedSubject,
        description: message.trim() || undefined,
        messageType,
      });
      toast.success(copy.successToast);
      onClose();
      await onSuccess();
    } catch (err) {
      const errorMessage =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : copy.errorFallback;
      setSubmitError(errorMessage);
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
        aria-labelledby="send-response-title"
        aria-modal="true"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2
            id="send-response-title"
            className="text-lg font-semibold text-slate-900"
          >
            {copy.title}
          </h2>
          <p className="mt-1 text-sm text-slate-600">{copy.dialogDescription}</p>
          {copy.showUnderReviewHelper ? (
            <p className="mt-2 text-sm text-[#006747]">
              Sending a response will move this case to Awaiting User Response.
            </p>
          ) : null}
        </div>

        <form onSubmit={(event) => void handleSubmit(event)} className="flex flex-col">
          <div className="space-y-4 px-5 py-4">
            {submitError ? <ErrorAlert message={submitError} /> : null}
            <div>
              <FieldLabel htmlFor="send-response-type" required>
                Type
              </FieldLabel>
              <select
                id="send-response-type"
                value={messageType}
                onChange={(event) =>
                  setMessageType(event.target.value as DispatcherServiceCaseMessageType)
                }
                className={triageFieldClassName}
                disabled={isSubmitting}
              >
                {MESSAGE_TYPE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <p className="mt-1.5 text-xs text-slate-600">
                {selectedTypeOption.helper}
              </p>
            </div>
            <div>
              <FieldLabel htmlFor="send-response-subject" required>
                Subject
              </FieldLabel>
              <input
                id="send-response-subject"
                type="text"
                value={subject}
                onChange={(event) => setSubject(event.target.value)}
                className={triageFieldClassName}
                maxLength={255}
                required
                disabled={isSubmitting}
              />
              {subjectError ? (
                <p className="mt-1 text-xs text-red-600">{subjectError}</p>
              ) : null}
            </div>
            <div>
              <FieldLabel htmlFor="send-response-message">Message</FieldLabel>
              <textarea
                id="send-response-message"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                className={triageFieldClassName}
                rows={5}
                placeholder="Additional details for the reporter"
                disabled={isSubmitting}
              />
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
            <Button type="submit" size="sm" isLoading={isSubmitting} disabled={isSubmitting}>
              {copy.submitLabel}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
