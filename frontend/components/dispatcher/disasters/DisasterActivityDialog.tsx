"use client";

import { createPortal } from "react-dom";
import { DisasterActivitySections } from "@/components/dispatcher/disasters/disaster-activity-content";
import { Button } from "@/components/ui/Button";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

type DisasterActivityDialogProps = {
  open: boolean;
  dashboard: OperationsDisasterDashboard;
  includeAudit?: boolean;
  onClose: () => void;
};

export function DisasterActivityDialog({
  open,
  dashboard,
  includeAudit = true,
  onClose,
}: DisasterActivityDialogProps) {
  if (!open) return null;

  const dialog = (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4 py-6"
      onClick={onClose}
    >
      <div
        className="flex max-h-[min(90vh,720px)] w-full max-w-2xl min-h-0 flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="disaster-activity-title"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="disaster-activity-title"
            className="text-lg font-semibold text-slate-900"
          >
            Disaster Activity
          </h2>
          <p className="mt-0.5 text-xs text-slate-600">
            Declarations, status changes, and audit history.
          </p>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-5 py-4">
          <DisasterActivitySections
            dashboard={dashboard}
            includeAudit={includeAudit}
          />
        </div>

        <div className="flex shrink-0 justify-end border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );

  if (typeof document === "undefined") return null;
  return createPortal(dialog, document.body);
}
