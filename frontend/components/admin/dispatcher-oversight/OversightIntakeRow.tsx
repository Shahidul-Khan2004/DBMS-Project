"use client";

import Link from "next/link";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatReportStatus } from "@/lib/report-status";
import type { OperationsIntakeReport } from "@/types/operations-intake";

function formatIntakeLocation(report: OperationsIntakeReport): string {
  const location = report.location;
  if (!location) return "—";
  const text =
    location.place_name?.trim() || location.address_text?.trim() || null;
  return text ?? "—";
}

type OversightIntakeRowProps = {
  report: OperationsIntakeReport;
  onViewReport: (publicUuid: string) => void;
};

export function OversightIntakeRow({
  report,
  onViewReport,
}: OversightIntakeRowProps) {
  const triageHref = `/dashboard/dispatcher/intake-reports?report=${encodeURIComponent(report.public_uuid)}`;

  return (
    <li>
      <div
        className={`flex w-full flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 ${getDispatcherClickableCardRowClasses()}`}
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-slate-600">
              {report.report_code}
            </span>
            <Badge size="compact" tone={report.intake_status}>
              {formatReportStatus(report.intake_status)}
            </Badge>
            {report.has_service_case ? (
              <Badge size="compact" tone="neutral">
                Service case
              </Badge>
            ) : null}
            {report.has_incident ? (
              <Badge size="compact" tone="neutral">
                Incident
              </Badge>
            ) : null}
          </div>
          <p className="mt-1 text-sm font-semibold text-slate-900">
            {report.summary}
          </p>
          <p className="mt-1 text-xs text-slate-600">
            {formatBadgeLabel(report.category_code)}
            <span className="text-slate-300"> · </span>
            {formatIntakeLocation(report)}
            {report.reported_at ? (
              <>
                <span className="text-slate-300"> · </span>
                Reported {formatBangladeshTime(report.reported_at)}
              </>
            ) : null}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => onViewReport(report.public_uuid)}
            className="text-xs font-medium text-[#002D62] hover:underline"
          >
            View report
          </button>
          <Link
            href={triageHref}
            className="text-xs font-medium text-slate-600 hover:text-[#002D62] hover:underline"
          >
            Open in dispatcher triage
          </Link>
        </div>
      </div>
    </li>
  );
}
