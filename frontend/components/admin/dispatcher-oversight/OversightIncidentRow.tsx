"use client";

import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatIncidentStatus } from "@/lib/incident-status";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";

type OversightIncidentRowProps = {
  incident: OperationsIncidentRow;
};

export function OversightIncidentRow({ incident }: OversightIncidentRowProps) {
  const href = `/dashboard/dispatcher/incidents/${encodeURIComponent(incident.public_uuid)}`;

  return (
    <li>
      <Link
        href={href}
        className={`group flex w-full flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#002D62] ${getDispatcherClickableCardRowClasses()}`}
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            {incident.incident_code ? (
              <span className="font-mono text-xs text-slate-600">
                {incident.incident_code}
              </span>
            ) : null}
            <Badge size="compact" tone={incident.severity_code}>
              {formatBadgeLabel(incident.severity_code)}
            </Badge>
            <Badge size="compact" tone={incident.status_code}>
              {formatIncidentStatus(incident.status_code)}
            </Badge>
          </div>
          <p className="mt-1 text-sm font-semibold text-slate-900">
            {incident.title}
          </p>
          <p className="mt-1 text-xs text-slate-600">
            {incident.category_code
              ? formatBadgeLabel(incident.category_code)
              : "—"}
            {incident.reported_at ? (
              <>
                <span className="text-slate-300"> · </span>
                Reported {formatBangladeshTime(incident.reported_at)}
              </>
            ) : null}
            {incident.updated_at ? (
              <>
                <span className="text-slate-300"> · </span>
                Updated {formatBangladeshTime(incident.updated_at)}
              </>
            ) : null}
          </p>
        </div>
        <span className="flex shrink-0 items-center gap-0.5 text-xs font-medium text-[#002D62]">
          Review incident
          <ChevronRight
            className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
            aria-hidden
          />
        </span>
      </Link>
    </li>
  );
}
