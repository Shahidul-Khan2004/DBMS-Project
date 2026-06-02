"use client";

import { ArchiveServiceCaseRow } from "@/components/dispatcher/archive/ArchiveServiceCaseRow";
import { ServiceCaseQueueRowSkeleton } from "@/components/dispatcher/service-cases/ServiceCaseQueueRowSkeleton";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import type { ArchivePartialStreamError } from "@/components/dispatcher/archive/types";
import type { OperationsServiceCase } from "@/types/service-case";

interface ArchiveServiceCasesListProps {
  items: OperationsServiceCase[];
  emptyMessage: string;
  className?: string;
  isLoading?: boolean;
  error?: string | null;
  partialError?: ArchivePartialStreamError;
  hasMore?: boolean;
  onRetry?: () => void;
  onLoadMore?: () => void;
  onRetryPartialStream?: (stream: "closed" | "escalated") => void;
}

function formatCountLabel(count: number): string {
  if (count === 1) return "1 case";
  return `${count} cases`;
}

export function ArchiveServiceCasesList({
  items,
  emptyMessage,
  className = "",
  isLoading = false,
  error = null,
  partialError = null,
  hasMore = false,
  onRetry,
  onLoadMore,
  onRetryPartialStream,
}: ArchiveServiceCasesListProps) {
  return (
    <div className={`flex min-h-0 flex-1 flex-col overflow-hidden ${className}`.trim()}>
      {error ? (
        <div className="space-y-3 px-4 py-4">
          <ErrorAlert message={error} />
          {onRetry ? (
            <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
              Retry
            </Button>
          ) : null}
        </div>
      ) : (
        <>
          {partialError ? (
            <div className="shrink-0 space-y-2 border-b border-amber-100 bg-amber-50/80 px-4 py-3">
              <ErrorAlert
                message={
                  partialError.stream === "closed"
                    ? `Closed cases could not be loaded: ${partialError.message}`
                    : `Escalated cases could not be loaded: ${partialError.message}`
                }
              />
              {onRetryPartialStream ? (
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => onRetryPartialStream(partialError.stream)}
                >
                  Retry{" "}
                  {partialError.stream === "closed" ? "closed cases" : "escalated cases"}
                </Button>
              ) : null}
            </div>
          ) : null}

          {isLoading && items.length === 0 ? (
            <div className="min-h-0 flex-1 overflow-hidden">
              {Array.from({ length: 5 }).map((_, index) => (
                <ServiceCaseQueueRowSkeleton key={index} />
              ))}
            </div>
          ) : items.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-slate-500">
              <p>{emptyMessage}</p>
            </div>
          ) : (
            <ul className="min-h-0 flex-1 space-y-2 overflow-y-auto overscroll-y-contain px-4 py-2">
              {items.map((serviceCase) => (
                <ArchiveServiceCaseRow
                  key={serviceCase.public_uuid}
                  serviceCase={serviceCase}
                />
              ))}
            </ul>
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
        </>
      )}

      {!error && items.length > 0 ? (
        <div className="sr-only" aria-live="polite">
          {formatCountLabel(items.length)} in archive
        </div>
      ) : null}
    </div>
  );
}
