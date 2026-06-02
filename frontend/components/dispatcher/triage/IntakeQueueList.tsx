import { getIntakeColumnCountClasses } from "@/components/dispatcher/intake/intakeStatusStyles";
import { IntakeQueueCard } from "@/components/dispatcher/triage/IntakeQueueCard";
import { TriageQueuePagination } from "@/components/dispatcher/triage/TriageQueuePagination";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";

interface IntakeQueueListProps {
  items: IntakeQueueItem[];
  selectedId: string | null;
  queueEmpty: boolean;
  isFilteredEmpty: boolean;
  pendingLabel?: string;
  className?: string;
  isLoading?: boolean;
  queueError?: string | null;
  onSelect: (id: string) => void;
  onRetry?: () => void;
}

export function IntakeQueueList({
  items,
  selectedId,
  queueEmpty,
  isFilteredEmpty,
  pendingLabel,
  className = "",
  isLoading = false,
  queueError = null,
  onSelect,
  onRetry,
}: IntakeQueueListProps) {
  return (
    <section
      className={`flex min-h-0 flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm ${className}`.trim()}
    >
      <header className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-100 px-4 py-2">
        <h3 className="text-sm font-semibold text-slate-900">
          Pending Intake Reports
        </h3>
        {pendingLabel ? (
          <span
            className={`inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-xs font-semibold ${getIntakeColumnCountClasses()}`}
          >
            {pendingLabel}
          </span>
        ) : null}
      </header>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {queueError ? (
          <div className="space-y-3 px-4 py-4">
            <ErrorAlert message={queueError} />
            {onRetry ? (
              <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
                Retry
              </Button>
            ) : null}
          </div>
        ) : isLoading ? (
          <div className="space-y-3 px-4 py-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <div
                key={index}
                className="h-20 animate-pulse rounded-xl bg-slate-100"
                aria-hidden
              />
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-slate-500">
            {queueEmpty ? (
              <>
                <p className="font-medium text-slate-700">
                  No reports awaiting triage
                </p>
                <p className="mt-1">
                  All pending reports have been routed.
                </p>
              </>
            ) : isFilteredEmpty ? (
              <p>No reports match the selected filters.</p>
            ) : null}
          </div>
        ) : (
          <ul className="min-h-0 flex-1 space-y-2 overflow-y-auto overscroll-y-contain px-4 py-2">
            {items.map((item) => (
              <li key={item.id}>
                <IntakeQueueCard
                  item={item}
                  selected={item.id === selectedId}
                  onSelect={onSelect}
                />
              </li>
            ))}
          </ul>
        )}

        <footer className="shrink-0 border-t border-slate-100 px-4 py-2">
          <TriageQueuePagination />
        </footer>
      </div>
    </section>
  );
}
