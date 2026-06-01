"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { OversightServiceCaseRow } from "@/components/admin/dispatcher-oversight/OversightServiceCaseRow";
import { OversightTabToolbar } from "@/components/admin/dispatcher-oversight/OversightTabToolbar";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError } from "@/lib/api";
import { listOperationsServiceCases } from "@/lib/service-case-api";
import type { OperationsServiceCase } from "@/types/service-case";

const SERVICE_CASE_STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "submitted", label: "Submitted" },
  { value: "under_review", label: "Under Review" },
  { value: "awaiting_user_response", label: "Awaiting User Response" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
  { value: "cancelled", label: "Cancelled" },
  { value: "escalated_to_emergency", label: "Escalated To Emergency" },
];

function matchesServiceCaseSearch(
  serviceCase: OperationsServiceCase,
  query: string,
): boolean {
  const haystack = [
    serviceCase.case_code,
    serviceCase.title,
    serviceCase.status_code,
    serviceCase.priority_level,
    serviceCase.category_code,
    serviceCase.assigned_to_user_public_uuid,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(query);
}

export function OversightServiceCasesTab() {
  const [cases, setCases] = useState<OperationsServiceCase[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await listOperationsServiceCases({
        limit: 100,
        status: statusFilter || undefined,
      });
      setCases(data.service_cases ?? []);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError("You do not have permission to view service cases.");
      } else {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load service cases.",
        );
      }
      setCases([]);
    } finally {
      setIsLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const filteredCases = useMemo(() => {
    const trimmed = searchQuery.trim().toLowerCase();
    if (!trimmed) return cases;
    return cases.filter((serviceCase) =>
      matchesServiceCaseSearch(serviceCase, trimmed),
    );
  }, [cases, searchQuery]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <OversightTabToolbar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Search by code, title, status…"
        statusFilter={statusFilter}
        onStatusFilterChange={setStatusFilter}
        statusOptions={SERVICE_CASE_STATUS_OPTIONS}
        statusLabel="Case status"
        onRefresh={() => void load()}
        isRefreshing={isLoading}
      />

      {error ? <ErrorAlert message={error} /> : null}

      {isLoading ? (
        <LoadingSkeleton lines={6} />
      ) : filteredCases.length === 0 ? (
        <p className="py-8 text-center text-sm text-slate-500">
          {searchQuery.trim()
            ? "No service cases match your search."
            : "No service cases found."}
        </p>
      ) : (
        <ul className="flex flex-col gap-2">
          {filteredCases.map((serviceCase) => (
            <OversightServiceCaseRow
              key={serviceCase.public_uuid}
              serviceCase={serviceCase}
            />
          ))}
        </ul>
      )}
    </div>
  );
}
