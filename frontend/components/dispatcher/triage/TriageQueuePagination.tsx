import { Button } from "@/components/ui/Button";

/** Pagination deferred: merged dual-status pending fetch cannot expose accurate totals. */
export function TriageQueuePagination() {
  return (
    <div
      className="mt-3 flex shrink-0 items-center justify-between border-t border-slate-100 pt-3"
      aria-label="Pagination"
    >
      <Button
        type="button"
        variant="secondary"
        size="sm"
        disabled
        aria-disabled="true"
        className="cursor-not-allowed"
      >
        Previous
      </Button>
      <span className="text-xs font-medium text-slate-600">Page 1 of 3</span>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        disabled
        aria-disabled="true"
        className="cursor-not-allowed"
      >
        Next
      </Button>
    </div>
  );
}
