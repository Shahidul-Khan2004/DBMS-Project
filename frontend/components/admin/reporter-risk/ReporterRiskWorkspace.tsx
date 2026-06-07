"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { ReporterRiskDetailDrawer } from "@/components/admin/reporter-risk/ReporterRiskDetailDrawer";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import {
  fetchAdminReporterRisks,
  formatRiskLevelLabel,
  getReporterRiskErrorMessage,
} from "@/lib/reporter-risk-api";
import type { ReporterRiskSummary } from "@/types/reporter-risk";

function SummaryCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "default" | "warning" | "danger";
}) {
  const valueClass =
    tone === "danger"
      ? "text-[#991B1B]"
      : tone === "warning"
        ? "text-amber-800"
        : "text-slate-900";

  return (
    <div className="rounded-xl border border-slate-200/90 bg-white px-4 py-3 shadow-sm">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${valueClass}`}>
        {value}
      </p>
    </div>
  );
}

export function ReporterRiskWorkspace() {
  const [reporters, setReporters] = useState<ReporterRiskSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedUuid, setSelectedUuid] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState<"" | "high" | "medium" | "low">("");

  const loadReporters = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAdminReporterRisks({
        limit: 100,
        offset: 0,
        sort: "risk_desc",
        ...(riskFilter ? { riskLevel: riskFilter } : {}),
      });
      setReporters(data.reporters ?? []);
    } catch (err) {
      setError(getReporterRiskErrorMessage(err, "Unable to load reporter risk data."));
      setReporters([]);
    } finally {
      setLoading(false);
    }
  }, [riskFilter]);

  useEffect(() => {
    void loadReporters();
  }, [loadReporters]);

  const highCount = reporters.filter((r) => r.risk_level === "high").length;
  const mediumCount = reporters.filter((r) => r.risk_level === "medium").length;
  const suspendedCount = reporters.filter((r) => r.account_status === "suspended").length;
  const malicious30d = reporters.reduce(
    (sum, r) => sum + (r.malicious_false_reports_30d ?? 0),
    0,
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 lg:overflow-hidden">
      <AdminPageHeader
        title="False Report Monitoring"
        subtitle="Review reporter reliability and take graduated account actions for confirmed abuse."
      />

      <p className="text-xs leading-relaxed text-slate-600">
        Use account restrictions only for repeated confirmed malicious false reports.
        Mistaken or duplicate reports should not be punished as abuse.
      </p>

      <div className="grid shrink-0 grid-cols-2 gap-3 lg:grid-cols-4">
        <SummaryCard label="High-risk reporters" value={highCount} tone="danger" />
        <SummaryCard label="Medium-risk reporters" value={mediumCount} tone="warning" />
        <SummaryCard label="Suspended users" value={suspendedCount} />
        <SummaryCard label="Malicious false (30d)" value={malicious30d} tone="danger" />
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-2">
        <label className="text-xs font-medium text-slate-600" htmlFor="risk-filter">
          Risk level
        </label>
        <select
          id="risk-filter"
          className="rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-800"
          value={riskFilter}
          onChange={(e) =>
            setRiskFilter(e.target.value as "" | "high" | "medium" | "low")
          }
        >
          <option value="">All</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <Button type="button" variant="secondary" size="sm" onClick={() => void loadReporters()}>
          Refresh
        </Button>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-slate-200/80 bg-white shadow-sm">
        {error ? (
          <div className="p-4">
            <ErrorAlert message={error} />
          </div>
        ) : loading ? (
          <div className="p-4">
            <LoadingSkeleton lines={6} />
          </div>
        ) : reporters.length === 0 ? (
          <p className="p-6 text-center text-sm text-slate-500">
            No reporters with submitted reports match this filter.
          </p>
        ) : (
          <div className="min-h-0 flex-1 overflow-x-auto overflow-y-auto overscroll-y-contain">
            <table className="min-w-full text-left text-sm">
              <thead className="sticky top-0 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-semibold">Reporter</th>
                  <th className="px-3 py-2 font-semibold">Contact</th>
                  <th className="px-3 py-2 font-semibold">Status</th>
                  <th className="px-3 py-2 font-semibold">Reports</th>
                  <th className="px-3 py-2 font-semibold">False alarms</th>
                  <th className="px-3 py-2 font-semibold">Malicious</th>
                  <th className="px-3 py-2 font-semibold">False 30d</th>
                  <th className="px-3 py-2 font-semibold">Risk</th>
                  <th className="px-3 py-2 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {reporters.map((row) => (
                  <tr key={row.reporter_public_uuid} className="hover:bg-slate-50/80">
                    <td className="px-3 py-2 font-medium text-slate-900">
                      {row.reporter_full_name}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      <div>{row.reporter_phone_number ?? "—"}</div>
                      <div className="truncate max-w-[160px]">{row.reporter_email ?? "—"}</div>
                    </td>
                    <td className="px-3 py-2">
                      <Badge tone={row.account_status} size="compact">
                        {row.account_status.replace(/_/g, " ")}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 font-medium tabular-nums text-slate-900">
                      {row.total_reports}
                    </td>
                    <td className="px-3 py-2 font-medium tabular-nums text-slate-900">
                      {row.false_alarm_reports}
                    </td>
                    <td className="px-3 py-2 font-medium tabular-nums text-slate-900">
                      {row.malicious_false_reports}
                    </td>
                    <td className="px-3 py-2 font-medium tabular-nums text-slate-900">
                      {row.false_reports_30d}
                    </td>
                    <td className="px-3 py-2">
                      <Badge tone={row.risk_level} size="compact">
                        {formatRiskLevelLabel(row.risk_level)}
                      </Badge>
                    </td>
                    <td className="px-3 py-2">
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() => setSelectedUuid(row.reporter_public_uuid)}
                      >
                        View details
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ReporterRiskDetailDrawer
        userPublicUuid={selectedUuid}
        onClose={() => setSelectedUuid(null)}
        onUpdated={() => {
          toast.success("Reporter record updated.");
          void loadReporters();
        }}
      />
    </div>
  );
}
