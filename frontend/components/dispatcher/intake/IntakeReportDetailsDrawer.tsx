"use client";

import { useCallback, useEffect, useState } from "react";
import { X } from "lucide-react";
import {
  IntakeReportDetailsContent,
  type IntakeReportLinkContext,
} from "@/components/dispatcher/intake/IntakeReportDetailsContent";
import { Button } from "@/components/ui/Button";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { fetchIntakeReportDetail } from "@/lib/operations-intake-triage";
import type { OperationsIntakeReport } from "@/types/operations-intake";

export type IntakeReportDetailsDrawerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  reportPublicUuid: string | null;
  context: "command-center" | "incident-command";
  linkContext?: IntakeReportLinkContext | null;
};

export function IntakeReportDetailsDrawer({
  open,
  onOpenChange,
  reportPublicUuid,
  context,
  linkContext = null,
}: IntakeReportDetailsDrawerProps) {
  const [report, setReport] = useState<OperationsIntakeReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const trimmedUuid = reportPublicUuid?.trim() ?? "";
  const hasValidUuid = trimmedUuid.length > 0;

  const loadReport = useCallback(async () => {
    const uuid = reportPublicUuid?.trim();
    if (!uuid) return;

    setIsLoading(true);
    setLoadError(null);
    try {
      const detail = await fetchIntakeReportDetail(uuid);
      setReport(detail);
    } catch {
      setReport(null);
      setLoadError("Unable to load report details. Please try again.");
    } finally {
      setIsLoading(false);
    }
  }, [reportPublicUuid]);

  useEffect(() => {
    if (!open || !hasValidUuid) {
      setReport(null);
      setLoadError(null);
      setIsLoading(false);
      return;
    }
    void loadReport();
  }, [open, hasValidUuid, loadReport]);

  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onOpenChange(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onOpenChange]);

  if (!open) return null;

  const handleClose = () => onOpenChange(false);

  return (
    <div className="fixed inset-0 z-50" role="presentation">
      <button
        type="button"
        className="absolute inset-0 bg-black/40"
        aria-label="Close intake report details"
        onClick={handleClose}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Intake report details"
        className="absolute inset-y-0 right-0 flex w-full max-w-md flex-col border-l border-slate-200 bg-white shadow-2xl sm:max-w-lg"
      >
        <div className="flex shrink-0 items-center justify-between border-b border-slate-200 px-4 py-4 sm:px-5">
          <h2 className="text-sm font-semibold text-slate-900">
            Intake Report Details
          </h2>
          <button
            type="button"
            onClick={handleClose}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-600 transition-colors hover:bg-slate-50"
            aria-label="Close intake report details"
          >
            <X className="h-5 w-5" aria-hidden />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-4 py-4 sm:px-5 sm:py-5">
          {!hasValidUuid ? (
            <p className="text-center text-sm text-slate-600">
              Original intake report information is unavailable.
            </p>
          ) : isLoading ? (
            <LoadingSkeleton lines={6} />
          ) : loadError ? (
            <div className="rounded-lg border border-[#B91C1C]/25 bg-[#FEF2F2] p-4 text-center">
              <p className="text-sm text-[#991B1B]">{loadError}</p>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                className="mt-3"
                onClick={() => void loadReport()}
              >
                Retry
              </Button>
            </div>
          ) : report ? (
            <IntakeReportDetailsContent
              report={report}
              context={context}
              linkContext={linkContext}
            />
          ) : null}
        </div>
      </aside>
    </div>
  );
}
