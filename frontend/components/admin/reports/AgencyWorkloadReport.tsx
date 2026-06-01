"use client";

import { useCallback, useEffect, useState } from "react";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError } from "@/lib/api";
import { getAgencyWorkload } from "@/lib/admin-reports-api";
import type { OperationsAgencyWorkloadItem } from "@/types/operations-incident";

export function AgencyWorkloadReport() {
  const [rows, setRows] = useState<OperationsAgencyWorkloadItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    setForbidden(false);
    try {
      const data = await getAgencyWorkload();
      setRows(data.agencies);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setForbidden(true);
        setRows([]);
      } else {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load agency workload.",
        );
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (isLoading) {
    return <LoadingSkeleton lines={6} />;
  }

  if (forbidden) {
    return (
      <p className="py-6 text-center text-sm text-slate-600">
        You do not have permission to view agency workload reports.
      </p>
    );
  }

  if (error) {
    return <ErrorAlert message={error} />;
  }

  if (rows.length === 0) {
    return (
      <p className="py-6 text-center text-sm text-slate-600">
        No agency workload data returned.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[40rem] text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
            <th className="py-2 pr-4 font-medium">Agency</th>
            <th className="py-2 pr-4 font-medium">Active incidents</th>
            <th className="py-2 pr-4 font-medium">Units</th>
            <th className="py-2 pr-4 font-medium">Available</th>
            <th className="py-2 pr-4 font-medium">Busy</th>
            <th className="py-2 font-medium">Dispatches</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.agency_public_uuid} className="border-b border-slate-100">
              <td className="py-3 pr-4 font-medium text-slate-900">
                {row.agency_name}
              </td>
              <td className="py-3 pr-4">
                <Badge size="compact" tone={row.active_incidents > 0 ? "warning" : "neutral"}>
                  {formatBadgeLabel(String(row.active_incidents))}
                </Badge>
              </td>
              <td className="py-3 pr-4 text-slate-700">{row.total_units}</td>
              <td className="py-3 pr-4 text-slate-700">{row.available_units}</td>
              <td className="py-3 pr-4 text-slate-700">{row.busy_units}</td>
              <td className="py-3 text-slate-700">{row.total_dispatches}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
