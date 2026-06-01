"use client";

import { useCallback, useEffect, useState } from "react";
import type { IntakeLocationHistoryItem } from "@/types/intake";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  getOperationsIntakeLocationHistory,
  mapApiErrorToRouteMessage,
} from "@/lib/operations-intake-triage";

interface ReportedLocationHistoryDialogProps {
  open: boolean;
  reportPublicUuid: string | null;
  reportSummary?: string;
  onClose: () => void;
  title?: string;
}

function formatChangeKind(kind: string): string {
  if (kind === "initial_create") return "Initial Reported Location";
  if (kind === "location_patch") return "Location Updated";
  return kind.replace(/_/g, " ");
}

function formatHistoryLocation(
  location: IntakeLocationHistoryItem["location"],
): string {
  if (!location) return "Location unavailable";
  return (
    location.address_text?.trim() ||
    location.place_name?.trim() ||
    "Map location selected"
  );
}

export function ReportedLocationHistoryDialog({
  open,
  reportPublicUuid,
  reportSummary,
  onClose,
  title = "Reported Location History",
}: ReportedLocationHistoryDialogProps) {
  const [history, setHistory] = useState<IntakeLocationHistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    if (!reportPublicUuid) return;

    setLoading(true);
    setError(null);

    try {
      const data = await getOperationsIntakeLocationHistory(reportPublicUuid);
      setHistory(data.history ?? []);
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load location history", err);
      }
      setError(mapApiErrorToRouteMessage(err, "location"));
      setHistory([]);
    } finally {
      setLoading(false);
    }
  }, [reportPublicUuid]);

  useEffect(() => {
    if (!open || !reportPublicUuid) return;
    void loadHistory();
  }, [open, reportPublicUuid, loadHistory]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div
        className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="location-history-title"
      >
        <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-100 p-4">
          <div>
            <h2
              id="location-history-title"
              className="text-base font-semibold text-slate-900"
            >
              {title}
            </h2>
            {reportSummary ? (
              <p className="mt-0.5 text-sm text-slate-600">{reportSummary}</p>
            ) : null}
          </div>
          <Button type="button" variant="secondary" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          {loading ? (
            <LoadingSkeleton lines={4} />
          ) : error ? (
            <div className="space-y-3">
              <ErrorAlert message={error} />
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => void loadHistory()}
              >
                Retry
              </Button>
            </div>
          ) : history.length === 0 ? (
            <p className="text-sm text-slate-600">No location changes recorded.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {history.map((item, index) => (
                <li
                  key={`${item.changed_at}-${index}`}
                  className="py-3 first:pt-0 last:pb-0"
                >
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    {formatChangeKind(item.change_kind)}
                  </p>
                  <p className="mt-1 text-sm text-slate-900">
                    {formatHistoryLocation(item.location)}
                  </p>
                  {item.previous_location ? (
                    <p className="mt-1 text-xs text-slate-500">
                      Previous: {formatHistoryLocation(item.previous_location)}
                    </p>
                  ) : null}
                  <p className="mt-2 text-xs text-slate-500">
                    {formatBangladeshTime(item.changed_at)}
                    {" · "}
                    {item.changed_by?.full_name ?? "System"}
                    {item.changed_by?.actor_kind
                      ? ` (${item.changed_by.actor_kind})`
                      : ""}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
