"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { IntakeReportDetailsDrawer } from "@/components/dispatcher/intake/IntakeReportDetailsDrawer";
import { OversightIntakeRow } from "@/components/admin/dispatcher-oversight/OversightIntakeRow";
import { OversightTabToolbar } from "@/components/admin/dispatcher-oversight/OversightTabToolbar";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError } from "@/lib/api";
import { listOperationsIntakeReports } from "@/lib/operations-intake-triage";
import type { OperationsIntakeReport } from "@/types/operations-intake";

const INTAKE_STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "received", label: "Received" },
  { value: "under_review", label: "Under Review" },
  { value: "linked_to_case", label: "Linked To Service Case" },
  { value: "linked_to_incident", label: "Linked To Incident" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
  { value: "cancelled", label: "Cancelled" },
  { value: "duplicate", label: "Duplicate" },
  { value: "false_report", label: "False Report" },
];

function matchesIntakeSearch(report: OperationsIntakeReport, query: string): boolean {
  const haystack = [
    report.report_code,
    report.summary,
    report.intake_status,
    report.category_code,
    report.location?.address_text,
    report.location?.place_name,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(query);
}

export function OversightIntakeTab() {
  const [reports, setReports] = useState<OperationsIntakeReport[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedUuid, setSelectedUuid] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await listOperationsIntakeReports({
        intake_status: statusFilter || undefined,
      });
      setReports(data.intake_reports ?? []);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError("You do not have permission to view intake reports.");
      } else {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load intake reports.",
        );
      }
      setReports([]);
    } finally {
      setIsLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const filteredReports = useMemo(() => {
    const trimmed = searchQuery.trim().toLowerCase();
    if (!trimmed) return reports;
    return reports.filter((report) => matchesIntakeSearch(report, trimmed));
  }, [reports, searchQuery]);

  const handleViewReport = (publicUuid: string) => {
    setSelectedUuid(publicUuid);
    setDrawerOpen(true);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <OversightTabToolbar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Search by code, summary, status…"
        statusFilter={statusFilter}
        onStatusFilterChange={setStatusFilter}
        statusOptions={INTAKE_STATUS_OPTIONS}
        statusLabel="Intake status"
        onRefresh={() => void load()}
        isRefreshing={isLoading}
      />

      {error ? <ErrorAlert message={error} /> : null}

      {isLoading ? (
        <LoadingSkeleton lines={6} />
      ) : filteredReports.length === 0 ? (
        <p className="py-8 text-center text-sm text-slate-500">
          {searchQuery.trim()
            ? "No intake reports match your search."
            : "No intake reports found."}
        </p>
      ) : (
        <ul className="flex flex-col gap-2">
          {filteredReports.map((report) => (
            <OversightIntakeRow
              key={report.public_uuid}
              report={report}
              onViewReport={handleViewReport}
            />
          ))}
        </ul>
      )}

      <IntakeReportDetailsDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        reportPublicUuid={selectedUuid}
        context="command-center"
      />
    </div>
  );
}
