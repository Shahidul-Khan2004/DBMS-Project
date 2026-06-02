"use client";

import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
  getDeclarationStatusSummary,
} from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";
import { formatBangladeshTime } from "@/lib/datetime";

type DisasterOverviewTabProps = {
  dashboard: DisasterDashboardResponse;
};

export function DisasterOverviewTab({ dashboard }: DisasterOverviewTabProps) {
  const { disaster } = dashboard;
  const counts = [
    { label: "Affected areas", value: dashboard.affected_areas?.length ?? 0 },
    { label: "Responsibilities", value: dashboard.responsibilities?.length ?? 0 },
    { label: "Linked incidents", value: dashboard.linked_incidents?.length ?? 0 },
    { label: "Shelters", value: dashboard.shelters?.length ?? 0 },
    { label: "Relief hubs", value: dashboard.relief_hubs?.length ?? 0 },
    { label: "Relief requests", value: dashboard.relief_requests?.length ?? 0 },
  ];

  return (
    <CommandSectionCard title="Disaster overview">
      <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <dt className="text-xs font-medium text-slate-500">Status</dt>
          <dd className="mt-0.5">
            <Badge size="compact" tone="active">
              {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
            </Badge>
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-slate-500">Severity</dt>
          <dd className="mt-0.5 text-slate-900">
            {formatDisasterSeverityLabel(disaster.severity_level)}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-slate-500">Event type</dt>
          <dd className="mt-0.5 text-slate-900">
            {formatDisasterEventTypeLabel(
              disaster.event_type_code,
              disaster.event_type_name,
            )}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-slate-500">Event code</dt>
          <dd className="mt-0.5 font-mono text-slate-900">{disaster.event_code}</dd>
        </div>
        {disaster.started_at ? (
          <div>
            <dt className="text-xs font-medium text-slate-500">Started</dt>
            <dd className="mt-0.5 text-slate-900">
              {formatBangladeshTime(disaster.started_at)}
            </dd>
          </div>
        ) : null}
        {disaster.ended_at ? (
          <div>
            <dt className="text-xs font-medium text-slate-500">Ended</dt>
            <dd className="mt-0.5 text-slate-900">
              {formatBangladeshTime(disaster.ended_at)}
            </dd>
          </div>
        ) : null}
        <div className="sm:col-span-2 lg:col-span-3">
          <dt className="text-xs font-medium text-slate-500">Declarations</dt>
          <dd className="mt-0.5 text-slate-900">
            {getDeclarationStatusSummary(
              disaster.status_code,
              dashboard.declarations?.length ?? 0,
            )}
          </dd>
        </div>
      </dl>

      <div className="mt-4 flex flex-wrap gap-2">
        {counts.map((c) => (
          <span
            key={c.label}
            className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs text-slate-700"
          >
            <span className="font-semibold text-slate-900">{c.value}</span> {c.label}
          </span>
        ))}
      </div>

      {disaster.description ? (
        <div className="mt-4">
          <p className="text-xs font-medium text-slate-500">Description</p>
          <p className="mt-1 text-sm text-slate-700">{disaster.description}</p>
        </div>
      ) : null}

      {disaster.public_guidance ? (
        <div className="mt-4">
          <p className="text-xs font-medium text-slate-500">Public guidance</p>
          <p className="mt-1 text-sm text-slate-700">{disaster.public_guidance}</p>
        </div>
      ) : null}
    </CommandSectionCard>
  );
}
