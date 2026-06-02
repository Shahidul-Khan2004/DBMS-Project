"use client";

import { CommandPlaceholderAction } from "@/components/dispatcher/incidents/command/CommandPlaceholderAction";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import type { LinkedIntakeReport } from "@/types/incident-command";

const LINK_REPORT_MESSAGE =
  "Linking intake reports will be available in a later phase.";

export function IncidentCommandLinkedReportsCard({
  reports,
  className = "",
}: {
  reports: LinkedIntakeReport[];
  className?: string;
}) {
  return (
    <CommandSectionCard
      title="Linked Reports"
      headerAction={
        <CommandPlaceholderAction
          label="+ Link Report"
          comingSoonMessage={LINK_REPORT_MESSAGE}
        />
      }
      className={className}
      fillHeight
      scrollableBody={reports.length > 0}
    >
      {reports.length === 0 ? (
        <p className="text-sm text-slate-600">
          No intake reports linked to this incident.
        </p>
      ) : (
        <ul className="divide-y divide-slate-100">
          {reports.map((report) => (
            <li
              key={`${report.intakeReportCode}-${report.linkedAt}-${report.linkType}`}
              className="py-2.5 first:pt-0 last:pb-0"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-medium text-slate-500">
                  {report.intakeReportCode}
                </span>
                <Badge tone={report.linkType}>{report.linkTypeLabel}</Badge>
              </div>
              <p className="mt-0.5 text-sm text-slate-800">{report.summary}</p>
              <p className="mt-0.5 text-xs text-slate-500">
                Linked {formatBangladeshTime(report.linkedAt)}
              </p>
            </li>
          ))}
        </ul>
      )}
    </CommandSectionCard>
  );
}
