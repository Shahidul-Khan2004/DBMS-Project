"use client";

import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/Button";

type StatusOption = {
  value: string;
  label: string;
};

type OversightTabToolbarProps = {
  searchQuery: string;
  onSearchChange: (value: string) => void;
  searchPlaceholder?: string;
  statusFilter?: string;
  onStatusFilterChange?: (value: string) => void;
  statusOptions?: StatusOption[];
  statusLabel?: string;
  onRefresh: () => void;
  isRefreshing?: boolean;
};

export function OversightTabToolbar({
  searchQuery,
  onSearchChange,
  searchPlaceholder = "Search records…",
  statusFilter,
  onStatusFilterChange,
  statusOptions,
  statusLabel = "Status",
  onRefresh,
  isRefreshing = false,
}: OversightTabToolbarProps) {
  const showStatusFilter =
    statusOptions &&
    statusOptions.length > 0 &&
    onStatusFilterChange &&
    statusFilter !== undefined;

  return (
    <div className="flex shrink-0 flex-wrap items-end gap-3 border-b border-slate-100 pb-3">
      <div className="min-w-[12rem] flex-1">
        <label className="sr-only" htmlFor="oversight-search">
          Search
        </label>
        <input
          id="oversight-search"
          type="search"
          value={searchQuery}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder={searchPlaceholder}
          className="w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#002D62] focus:outline-none focus:ring-1 focus:ring-[#002D62]"
        />
      </div>
      {showStatusFilter ? (
        <div className="min-w-[10rem]">
          <label
            htmlFor="oversight-status-filter"
            className="mb-1 block text-xs font-medium text-slate-600"
          >
            {statusLabel}
          </label>
          <select
            id="oversight-status-filter"
            value={statusFilter}
            onChange={(event) => onStatusFilterChange(event.target.value)}
            className="w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-900 focus:border-[#002D62] focus:outline-none focus:ring-1 focus:ring-[#002D62]"
          >
            {statusOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      ) : null}
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={onRefresh}
        disabled={isRefreshing}
        className="shrink-0"
      >
        <RefreshCw
          className={`mr-1.5 h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`}
          aria-hidden
        />
        Refresh
      </Button>
    </div>
  );
}
