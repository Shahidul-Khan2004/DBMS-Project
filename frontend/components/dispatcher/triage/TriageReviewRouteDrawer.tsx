"use client";

import { useEffect } from "react";
import { TriageReviewRouteWorkspace } from "@/components/dispatcher/triage/TriageReviewRouteWorkspace";

export type TriageReviewRouteDrawerProps = {
  open: boolean;
  reportPublicUuid: string | null;
  onOpenChange: (open: boolean) => void;
  onRouteSuccess?: () => void | Promise<void>;
};

export function TriageReviewRouteDrawer({
  open,
  reportPublicUuid,
  onOpenChange,
  onRouteSuccess,
}: TriageReviewRouteDrawerProps) {
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

  const reportId = reportPublicUuid?.trim() || null;

  const handleClose = () => onOpenChange(false);

  return (
    <div className="fixed inset-0 z-50" role="presentation">
      <button
        type="button"
        className="absolute inset-0 bg-black/40"
        aria-label="Close review and route"
        onClick={handleClose}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Review and route intake report"
        className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-slate-200 bg-white shadow-2xl sm:w-[min(920px,55vw)]"
      >
        <TriageReviewRouteWorkspace
          reportId={reportId}
          enabled={open && Boolean(reportId)}
          queueEmpty={false}
          showPanelHeader={false}
          continueLabel="Continue Monitoring"
          continueAfterSuccess="close"
          onAfterRouteSuccess={onRouteSuccess}
          onRequestClose={handleClose}
          variant="drawer"
          embedded
          className="flex min-h-0 flex-1 flex-col"
        />
      </aside>
    </div>
  );
}
