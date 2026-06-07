"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import {
  CONFIDENCE_OPTIONS,
  getReporterRiskErrorMessage,
  submitIntakeVerification,
  VERDICT_OPTIONS,
} from "@/lib/reporter-risk-api";
import type { RecordVerificationPayload, ReporterRiskSummary } from "@/types/reporter-risk";

type RecordVerificationModalProps = {
  open: boolean;
  reportPublicUuid: string;
  onClose: () => void;
  onSuccess: (reporterRisk: ReporterRiskSummary | null) => void;
};

export function RecordVerificationModal({
  open,
  reportPublicUuid,
  onClose,
  onSuccess,
}: RecordVerificationModalProps) {
  const [verdict, setVerdict] = useState<RecordVerificationPayload["verdict"]>("genuine");
  const [confidenceLevel, setConfidenceLevel] =
    useState<RecordVerificationPayload["confidenceLevel"]>("medium");
  const [reason, setReason] = useState("");
  const [evidenceNote, setEvidenceNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [confirmMalicious, setConfirmMalicious] = useState(false);

  useEffect(() => {
    if (!open) return;
    setVerdict("genuine");
    setConfidenceLevel("medium");
    setReason("");
    setEvidenceNote("");
    setSubmitError(null);
    setConfirmMalicious(false);
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  useEffect(() => {
    if (verdict !== "malicious_false_report") {
      setConfirmMalicious(false);
    }
  }, [verdict]);

  if (!open) return null;

  const needsMaliciousConfirm =
    verdict === "malicious_false_report" && !confirmMalicious;

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitError(null);

    if (needsMaliciousConfirm) {
      setSubmitError(
        "Confirm that this is a deliberate malicious false report before submitting.",
      );
      return;
    }

    setIsSubmitting(true);
    try {
      const result = await submitIntakeVerification(reportPublicUuid, {
        verdict,
        confidenceLevel,
        reason: reason.trim() || undefined,
        evidenceNote: evidenceNote.trim() || undefined,
      });
      toast.success("Verification recorded.");
      onSuccess(result.reporter_risk ?? null);
      onClose();
    } catch (err) {
      setSubmitError(
        getReporterRiskErrorMessage(err, "Unable to record verification."),
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="Close verification dialog"
        className="absolute inset-0 bg-black/40"
        onClick={onClose}
      />
      <form
        onSubmit={handleSubmit}
        className="relative z-10 flex max-h-[min(90vh,640px)] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-lg"
      >
        <header className="shrink-0 border-b border-slate-100 px-4 py-3">
          <h3 className="text-sm font-semibold text-slate-900">Record Verification</h3>
          <p className="mt-0.5 text-xs text-slate-600">
            Document dispatcher assessment of this intake report.
          </p>
        </header>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-3">
          {submitError ? <ErrorAlert message={submitError} /> : null}

          <div>
            <FieldLabel htmlFor="verification-verdict" required>
              Verdict
            </FieldLabel>
            <select
              id="verification-verdict"
              className={triageFieldClassName}
              value={verdict}
              onChange={(e) =>
                setVerdict(e.target.value as RecordVerificationPayload["verdict"])
              }
            >
              {VERDICT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <FieldLabel htmlFor="verification-confidence">Confidence level</FieldLabel>
            <select
              id="verification-confidence"
              className={triageFieldClassName}
              value={confidenceLevel}
              onChange={(e) =>
                setConfidenceLevel(
                  e.target.value as RecordVerificationPayload["confidenceLevel"],
                )
              }
            >
              {CONFIDENCE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <FieldLabel htmlFor="verification-reason">Reason</FieldLabel>
            <input
              id="verification-reason"
              className={triageFieldClassName}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={255}
              placeholder="Brief reason for this verdict"
            />
          </div>

          <div>
            <FieldLabel htmlFor="verification-evidence">Evidence note</FieldLabel>
            <textarea
              id="verification-evidence"
              className={`${triageFieldClassName} min-h-[88px] resize-y`}
              value={evidenceNote}
              onChange={(e) => setEvidenceNote(e.target.value)}
              maxLength={2000}
              placeholder="Field checks, agency confirmation, or call-back notes"
            />
          </div>

          {verdict === "malicious_false_report" ? (
            <label className="flex cursor-pointer items-start gap-2 rounded-md border border-[#B91C1C]/30 bg-[#FEF2F2] px-3 py-2 text-xs text-[#991B1B]">
              <input
                type="checkbox"
                checked={confirmMalicious}
                onChange={(e) => setConfirmMalicious(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                I confirm this is a deliberate malicious false report, not a mistaken or
                duplicate submission.
              </span>
            </label>
          ) : null}
        </div>

        <footer className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-4 py-3">
          <Button type="button" variant="secondary" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" size="sm" isLoading={isSubmitting} disabled={isSubmitting}>
            Submit verification
          </Button>
        </footer>
      </form>
    </div>
  );
}
