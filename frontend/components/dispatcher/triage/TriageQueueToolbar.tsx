import {
  TRIAGE_CATEGORY_FILTER_OPTIONS,
  TRIAGE_SORT_OPTIONS,
  TRIAGE_STATUS_FILTER_OPTIONS,
} from "@/components/dispatcher/triage/toolbarConfig";
import type {
  TriageCategoryFilter,
  TriageSortOrder,
  TriageStatusFilter,
} from "@/components/dispatcher/triage/types";

const selectClassName =
  "h-9 w-full min-w-0 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-900 focus:border-[#002D62]/40 focus:outline-none focus:ring-2 focus:ring-[#002D62]/15";

interface TriageQueueToolbarProps {
  statusFilter: TriageStatusFilter;
  categoryFilter: TriageCategoryFilter;
  sortOrder: TriageSortOrder;
  onStatusChange: (value: TriageStatusFilter) => void;
  onCategoryChange: (value: TriageCategoryFilter) => void;
  onSortChange: (value: TriageSortOrder) => void;
}

export function TriageQueueToolbar({
  statusFilter,
  categoryFilter,
  sortOrder,
  onStatusChange,
  onCategoryChange,
  onSortChange,
}: TriageQueueToolbarProps) {
  return (
    <div className="grid shrink-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-[1fr_1.2fr_0.9fr]">
      <label className="sr-only" htmlFor="triage-status-filter">
        Status
      </label>
      <select
        id="triage-status-filter"
        value={statusFilter}
        onChange={(event) =>
          onStatusChange(event.target.value as TriageStatusFilter)
        }
        className={selectClassName}
      >
        {TRIAGE_STATUS_FILTER_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="triage-category-filter">
        Category
      </label>
      <select
        id="triage-category-filter"
        value={categoryFilter}
        onChange={(event) =>
          onCategoryChange(event.target.value as TriageCategoryFilter)
        }
        className={selectClassName}
      >
        {TRIAGE_CATEGORY_FILTER_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="triage-sort-filter">
        Sort
      </label>
      <select
        id="triage-sort-filter"
        value={sortOrder}
        onChange={(event) => onSortChange(event.target.value as TriageSortOrder)}
        className={selectClassName}
      >
        {TRIAGE_SORT_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      {/* Reserved slot for future Area / Location filter */}
      <div data-slot="area-filter" className="hidden" aria-hidden />
    </div>
  );
}
