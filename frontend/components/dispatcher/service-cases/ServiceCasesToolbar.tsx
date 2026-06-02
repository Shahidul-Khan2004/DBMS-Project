import {
  SERVICE_CASE_CATEGORY_FILTER_OPTIONS,
  SERVICE_CASE_PRIORITY_FILTER_OPTIONS,
  SERVICE_CASE_SORT_OPTIONS,
  SERVICE_CASE_STATUS_FILTER_OPTIONS,
  type ServiceCaseSortOrder,
} from "@/components/dispatcher/service-cases/toolbarConfig";
import { Button } from "@/components/ui/Button";

const selectClassName =
  "h-9 w-full min-w-0 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-900 focus:border-[#002D62]/40 focus:outline-none focus:ring-2 focus:ring-[#002D62]/15";

export interface ServiceCasesFilters {
  status: string;
  categoryCode: string;
}

interface ServiceCasesToolbarProps {
  filters: ServiceCasesFilters;
  priorityFilter: string;
  sortOrder: ServiceCaseSortOrder;
  isLoading: boolean;
  onFiltersChange: (patch: Partial<ServiceCasesFilters>) => void;
  onPriorityFilterChange: (value: string) => void;
  onSortOrderChange: (value: ServiceCaseSortOrder) => void;
  onApply: () => void;
}

export function ServiceCasesToolbar({
  filters,
  priorityFilter,
  sortOrder,
  isLoading,
  onFiltersChange,
  onPriorityFilterChange,
  onSortOrderChange,
  onApply,
}: ServiceCasesToolbarProps) {
  return (
    <div className="grid shrink-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_1.2fr_1fr_auto] lg:items-end">
      <label className="sr-only" htmlFor="service-case-status-filter">
        Status
      </label>
      <select
        id="service-case-status-filter"
        value={filters.status}
        onChange={(event) => onFiltersChange({ status: event.target.value })}
        className={selectClassName}
      >
        {SERVICE_CASE_STATUS_FILTER_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="service-case-priority-filter">
        Priority
      </label>
      <select
        id="service-case-priority-filter"
        value={priorityFilter}
        onChange={(event) => onPriorityFilterChange(event.target.value)}
        className={selectClassName}
      >
        {SERVICE_CASE_PRIORITY_FILTER_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="service-case-category-filter">
        Category
      </label>
      <select
        id="service-case-category-filter"
        value={filters.categoryCode}
        onChange={(event) => onFiltersChange({ categoryCode: event.target.value })}
        className={selectClassName}
      >
        {SERVICE_CASE_CATEGORY_FILTER_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="service-case-sort">
        Sort
      </label>
      <select
        id="service-case-sort"
        value={sortOrder}
        onChange={(event) =>
          onSortOrderChange(event.target.value as ServiceCaseSortOrder)
        }
        className={selectClassName}
      >
        {SERVICE_CASE_SORT_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-9 shrink-0"
        onClick={onApply}
        disabled={isLoading}
      >
        Apply Filters
      </Button>
    </div>
  );
}
