"use client";

import { ArchiveIncidentRow } from "@/components/dispatcher/archive/ArchiveIncidentRow";
import { DISPATCHER_EMERGENCY_ALERT_PANEL_CLASSES } from "@/components/dispatcher/emergencyColors";
import type { ActiveIncidentListItem, IncidentCardLocationState } from "@/components/dispatcher/incidents/types";
import { Button } from "@/components/ui/Button";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";

interface ArchiveIncidentsListProps {
  items: ActiveIncidentListItem[];
  sourceRows: OperationsIncidentRow[];
  getCardLocation: (publicUuid: string) => IncidentCardLocationState;
  emptyMessage: string;
  className?: string;
  isLoading?: boolean;
  error?: string | null;
  hasMore?: boolean;
  onRetry?: () => void;
  onLoadMore?: () => void;
}

function ArchiveIncidentRowSkeleton() {
  return (
    <div
      className="h-[6.5rem] animate-pulse rounded-xl border border-slate-200/80 bg-white"
      aria-hidden
    />
  );
}

export function ArchiveIncidentsList({
  items,
  sourceRows,
  getCardLocation,
  emptyMessage,
  className = "",
  isLoading = false,
  error = null,
  hasMore = false,
  onRetry,
  onLoadMore,
}: ArchiveIncidentsListProps) {
  const sourceRowByUuid = new Map(
    sourceRows.map((row) => [row.public_uuid, row]),
  );

  return (
    <div className={`flex min-h-0 flex-1 flex-col overflow-hidden ${className}`.trim()}>
      {error ? (
        <div className="space-y-3 px-4 py-4">
          <div className={`rounded-2xl border p-6 text-center shadow-sm ${DISPATCHER_EMERGENCY_ALERT_PANEL_CLASSES}`}>
            <h3 className="font-semibold text-[#991B1B]">Unable to load archived incidents</h3>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-[#991B1B]">{error}</p>
            {onRetry ? (
              <div className="mt-4 flex justify-center">
                <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
                  Retry
                </Button>
              </div>
            ) : null}
          </div>
        </div>
      ) : isLoading && items.length === 0 ? (
        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto overscroll-y-contain px-4 py-4 lg:min-h-0">
          {Array.from({ length: 4 }).map((_, index) => (
            <ArchiveIncidentRowSkeleton key={index} />
          ))}
        </div>
      ) : items.length === 0 ? (
        <div className="px-4 py-8 text-center text-sm text-slate-500">
          <p>{emptyMessage}</p>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto overscroll-y-contain px-4 py-4 pr-4.5 lg:min-h-0">
          {items.map((incident) => {
            const sourceRow = sourceRowByUuid.get(incident.publicUuid);
            if (!sourceRow) return null;

            return (
              <ArchiveIncidentRow
                key={incident.publicUuid}
                incident={incident}
                sourceRow={sourceRow}
                locationState={getCardLocation(incident.publicUuid)}
              />
            );
          })}
        </div>
      )}

      {hasMore && !error ? (
        <footer className="flex shrink-0 justify-center border-t border-slate-100 px-4 py-3">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={isLoading}
            onClick={onLoadMore}
          >
            {isLoading ? "Loading…" : "Load more"}
          </Button>
        </footer>
      ) : null}
    </div>
  );
}
