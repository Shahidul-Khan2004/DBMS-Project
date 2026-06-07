"use client";

import { DisasterOpsCard } from "@/components/dispatcher/disasters/DisasterOpsCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function DisasterContextCard({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  const { disaster } = dashboard;
  const areaCount = dashboard.affected_areas?.length ?? 0;
  const linkedCount = dashboard.linked_incidents?.length ?? 0;

  return (
    <DisasterOpsCard title="Disaster Context">
      <dl className="space-y-2.5 text-sm">
        <div>
          <dt className="text-xs font-medium text-slate-500">Event code</dt>
          <dd className="mt-0.5 font-medium text-slate-900">{disaster.event_code}</dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-slate-500">Title</dt>
          <dd className="mt-0.5 font-semibold text-slate-900">{disaster.title}</dd>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge size="compact" tone="active">
            {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
          </Badge>
          <Badge size="compact" tone="neutral">
            {formatDisasterSeverityLabel(disaster.severity_level)}
          </Badge>
          <Badge size="compact" tone="neutral">
            {formatDisasterEventTypeLabel(
              disaster.event_type_code,
              disaster.event_type_name,
            )}
          </Badge>
        </div>
        {disaster.started_at ? (
          <div>
            <dt className="text-xs font-medium text-slate-500">Started</dt>
            <dd className="mt-0.5 text-slate-900">
              {formatBangladeshTime(disaster.started_at)}
            </dd>
          </div>
        ) : null}
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
          <span>
            {areaCount} affected area{areaCount === 1 ? "" : "s"}
          </span>
          <span>
            {linkedCount} linked incident{linkedCount === 1 ? "" : "s"}
          </span>
        </div>
        {disaster.public_guidance ? (
          <div>
            <dt className="text-xs font-medium text-slate-500">Public guidance</dt>
            <dd className="mt-0.5 text-slate-700">{disaster.public_guidance}</dd>
          </div>
        ) : null}
      </dl>
    </DisasterOpsCard>
  );
}
