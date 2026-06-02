"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { OversightIncidentRow } from "@/components/admin/dispatcher-oversight/OversightIncidentRow";
import { OversightTabToolbar } from "@/components/admin/dispatcher-oversight/OversightTabToolbar";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError } from "@/lib/api";
import {
  getOperationsIncidents,
  type OperationsIncidentRow,
} from "@/lib/operations-intake-triage";

const INCIDENT_STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "reported", label: "Reported" },
  { value: "classified", label: "Classified" },
  { value: "in_progress", label: "In Progress" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
  { value: "cancelled", label: "Cancelled" },
];

function matchesIncidentSearch(
  incident: OperationsIncidentRow,
  query: string,
): boolean {
  const haystack = [
    incident.incident_code,
    incident.title,
    incident.status_code,
    incident.severity_code,
    incident.category_code,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(query);
}

export function OversightIncidentsTab() {
  const [incidents, setIncidents] = useState<OperationsIncidentRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getOperationsIncidents({
        limit: 100,
        status_code: statusFilter || undefined,
      });
      setIncidents(data.incidents ?? []);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError("You do not have permission to view incidents.");
      } else {
        setError(
          err instanceof Error ? err.message : "Failed to load incidents.",
        );
      }
      setIncidents([]);
    } finally {
      setIsLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const filteredIncidents = useMemo(() => {
    const trimmed = searchQuery.trim().toLowerCase();
    if (!trimmed) return incidents;
    return incidents.filter((incident) =>
      matchesIncidentSearch(incident, trimmed),
    );
  }, [incidents, searchQuery]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <OversightTabToolbar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Search by code, title, status…"
        statusFilter={statusFilter}
        onStatusFilterChange={setStatusFilter}
        statusOptions={INCIDENT_STATUS_OPTIONS}
        statusLabel="Incident status"
        onRefresh={() => void load()}
        isRefreshing={isLoading}
      />

      {error ? <ErrorAlert message={error} /> : null}

      {isLoading ? (
        <LoadingSkeleton lines={6} />
      ) : filteredIncidents.length === 0 ? (
        <p className="py-8 text-center text-sm text-slate-500">
          {searchQuery.trim()
            ? "No incidents match your search."
            : "No incidents found."}
        </p>
      ) : (
        <ul className="flex flex-col gap-2">
          {filteredIncidents.map((incident) => (
            <OversightIncidentRow
              key={incident.public_uuid}
              incident={incident}
            />
          ))}
        </ul>
      )}
    </div>
  );
}
