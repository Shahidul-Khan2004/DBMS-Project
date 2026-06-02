"use client";

import { getServiceCaseColumnCountClasses } from "@/components/dispatcher/service-cases/priorityStyles";
import { ServiceCaseQueueRow } from "@/components/dispatcher/service-cases/ServiceCaseQueueRow";
import { ServiceCaseQueueRowSkeleton } from "@/components/dispatcher/service-cases/ServiceCaseQueueRowSkeleton";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import type { OperationsServiceCase } from "@/types/service-case";

interface ServiceCaseQueuePagination {
  limit: number;
  offset: number;
  total: number;
}

interface ServiceCaseQueueListProps {
  items: OperationsServiceCase[];
  countLabel: string;
  className?: string;
  isLoading?: boolean;
  error?: string | null;
  pagination?: ServiceCaseQueuePagination;
  onRetry?: () => void;
  onPreviousPage?: () => void;
  onNextPage?: () => void;
}

function formatCountLabel(count: number): string {
  if (count === 1) return "1 case";
  return `${count} cases`;
}

export function ServiceCaseQueueList({
  items,
  countLabel,
  className = "",
  isLoading = false,
  error = null,
  pagination,
  onRetry,
  onPreviousPage,
  onNextPage,
}: ServiceCaseQueueListProps) {
  const showPagination =
    pagination != null && pagination.total > pagination.limit;
  const currentPage =
    pagination != null
      ? Math.floor(pagination.offset / pagination.limit) + 1
      : 1;
  const totalPages =
    pagination != null
      ? Math.ceil(pagination.total / pagination.limit)
      : 1;

  return (
    <section
      className={`flex min-h-0 flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm lg:min-h-0 ${className}`.trim()}
      aria-label="Service case queue"
    >
      <header className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-100 px-4 py-3">
        <h3 className="text-sm font-semibold text-slate-900">Service Case Queue</h3>
        <span
          className={`inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-xs font-semibold ${getServiceCaseColumnCountClasses()}`}
        >
          {countLabel || formatCountLabel(items.length)}
        </span>
      </header>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {error ? (
          <div className="space-y-3 px-4 py-4">
            <ErrorAlert message={error} />
            {onRetry ? (
              <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
                Retry
              </Button>
            ) : null}
          </div>
        ) : isLoading && items.length === 0 ? (
          <div className="min-h-0 flex-1 overflow-hidden">
            {Array.from({ length: 5 }).map((_, index) => (
              <ServiceCaseQueueRowSkeleton key={index} />
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-slate-500">
            <p>No service cases match the selected filters.</p>
          </div>
        ) : (
          <ul className="min-h-0 flex-1 space-y-2 overflow-y-auto overscroll-y-contain px-4 py-2">
            {items.map((serviceCase) => (
              <ServiceCaseQueueRow
                key={serviceCase.public_uuid}
                serviceCase={serviceCase}
              />
            ))}
          </ul>
        )}

        {showPagination && pagination ? (
          <footer className="flex shrink-0 items-center justify-between gap-3 border-t border-slate-100 px-4 py-2">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={pagination.offset === 0 || isLoading}
              onClick={onPreviousPage}
            >
              Previous
            </Button>
            <span className="text-sm text-slate-600">
              Page {currentPage} of {totalPages}
            </span>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={
                pagination.offset + pagination.limit >= pagination.total ||
                isLoading
              }
              onClick={onNextPage}
            >
              Next
            </Button>
          </footer>
        ) : null}
      </div>
    </section>
  );
}
