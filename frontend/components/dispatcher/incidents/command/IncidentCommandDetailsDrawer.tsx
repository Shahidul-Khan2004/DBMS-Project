"use client";

import { useEffect } from "react";
import { X } from "lucide-react";
import { IncidentCommandDetailsContent } from "@/components/dispatcher/incidents/command/IncidentCommandDetailsContent";
import type { IncidentDetailResponse } from "@/types/incident-command";

export function IncidentCommandDetailsDrawer({
  open,
  onClose,
  detail,
  sourceLabel,
  canEditLocation = false,
  canViewLocationHistory = false,
  onEditLocation,
  onViewLocationHistory,
}: {
  open: boolean;
  onClose: () => void;
  detail: IncidentDetailResponse;
  sourceLabel: string;
  canEditLocation?: boolean;
  canViewLocationHistory?: boolean;
  onEditLocation?: () => void;
  onViewLocationHistory?: () => void;
}) {
  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50" role="presentation">
      <button
        type="button"
        className="absolute inset-0 bg-black/40"
        aria-label="Close incident details"
        onClick={onClose}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Incident details"
        className="absolute inset-y-0 right-0 flex w-full max-w-md flex-col border-l border-slate-200 bg-white shadow-2xl sm:max-w-lg"
      >
        <div className="flex shrink-0 items-center justify-between border-b border-slate-200 px-4 py-4 sm:px-5">
          <h2 className="text-sm font-semibold text-slate-900">
            Incident Details
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-600 transition-colors hover:bg-slate-50"
            aria-label="Close incident details"
          >
            <X className="h-5 w-5" aria-hidden />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-4 py-4 sm:px-5 sm:py-5">
          <IncidentCommandDetailsContent
            detail={detail}
            sourceLabel={sourceLabel}
            canEditLocation={canEditLocation}
            canViewLocationHistory={canViewLocationHistory}
            onEditLocation={onEditLocation}
            onViewLocationHistory={onViewLocationHistory}
          />
        </div>
      </aside>
    </div>
  );
}
