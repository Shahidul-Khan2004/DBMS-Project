import {
  ACTIVE_INCIDENTS_DATE_OPTIONS,
  ACTIVE_INCIDENTS_STATUS_OPTIONS,
} from "@/components/dispatcher/incidents/toolbarConfig";
import type {
  ActiveIncidentsDateFilter,
  ActiveIncidentsStatusFilter,
} from "@/components/dispatcher/incidents/types";

const selectClassName =
  "h-9 w-full min-w-0 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-900 focus:border-[#002D62]/40 focus:outline-none focus:ring-2 focus:ring-[#002D62]/15";

interface ActiveIncidentsToolbarProps {
  statusFilter: ActiveIncidentsStatusFilter;
  dateFilter: ActiveIncidentsDateFilter;
  resultCount: number;
  onStatusChange: (value: ActiveIncidentsStatusFilter) => void;
  onDateChange: (value: ActiveIncidentsDateFilter) => void;
}

function formatResultText(count: number): string {
  if (count === 1) return "Showing 1 active incident";
  return `Showing ${count} active incidents`;
}

export function ActiveIncidentsToolbar({
  statusFilter,
  dateFilter,
  resultCount,
  onStatusChange,
  onDateChange,
}: ActiveIncidentsToolbarProps) {
  return (
    <div className="flex shrink-0 flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-3 lg:max-w-xl">
        <label className="sr-only" htmlFor="active-incidents-status-filter">
          Status
        </label>
        <select
          id="active-incidents-status-filter"
          value={statusFilter}
          onChange={(event) =>
            onStatusChange(event.target.value as ActiveIncidentsStatusFilter)
          }
          className={selectClassName}
        >
          {ACTIVE_INCIDENTS_STATUS_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <label className="sr-only" htmlFor="active-incidents-date-filter">
          Date range
        </label>
        <select
          id="active-incidents-date-filter"
          value={dateFilter}
          onChange={(event) =>
            onDateChange(event.target.value as ActiveIncidentsDateFilter)
          }
          className={selectClassName}
        >
          {ACTIVE_INCIDENTS_DATE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      <p className="shrink-0 text-sm text-slate-600">{formatResultText(resultCount)}</p>
    </div>
  );
}
