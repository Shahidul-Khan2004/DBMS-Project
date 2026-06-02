"use client";

import { formatBangladeshTime } from "@/lib/datetime";
import { formatResponseDurationMinutes } from "@/lib/format-response-duration";
import type { OperationsResponseTiming } from "@/types/operations-incident";

function formatMetricValue(
  minutes: number | null,
  milestoneAt: string | null,
): string {
  if (milestoneAt === null) {
    return "Pending";
  }
  if (minutes === null) {
    return "Pending";
  }
  return formatResponseDurationMinutes(minutes);
}

function MetricTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2.5">
      <p className="text-[11px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <p className="mt-1 text-lg font-semibold text-slate-900">{value}</p>
    </div>
  );
}

function PipelineRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-100 py-2 last:border-b-0">
      <span className="text-sm text-slate-600">{label}</span>
      <span className="shrink-0 text-right text-sm font-medium text-slate-900">
        {value}
      </span>
    </div>
  );
}

function formatPipelineTimestamp(value: string | null): string {
  if (!value) {
    return "Pending";
  }
  return formatBangladeshTime(value);
}

export function ResponseTimingDisplay({
  timing,
}: {
  timing: OperationsResponseTiming;
}) {
  const showCallToIncident = Boolean(timing.first_call_started_at);

  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm font-semibold text-slate-900">
          {timing.incident_code}
        </p>
        <p className="mt-0.5 text-xs text-slate-600">
          Incident response pipeline timing
        </p>
      </div>

      <div className="grid gap-2 sm:grid-cols-2">
        {showCallToIncident ? (
          <MetricTile
            label="Call → Incident"
            value={formatMetricValue(
              timing.call_to_incident_minutes,
              timing.first_call_started_at,
            )}
          />
        ) : null}
        <MetricTile
          label="Incident → Agency"
          value={formatMetricValue(
            timing.incident_to_agency_minutes,
            timing.first_agency_joined_at,
          )}
        />
        <MetricTile
          label="Agency → Dispatch"
          value={formatMetricValue(
            timing.agency_to_dispatch_minutes,
            timing.first_unit_dispatched_at,
          )}
        />
        <MetricTile
          label="Dispatch → Arrival"
          value={formatMetricValue(
            timing.dispatch_to_arrival_minutes,
            timing.first_unit_arrived_at,
          )}
        />
      </div>

      <div>
        <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Response pipeline
        </h5>
        <div className="mt-2 rounded-lg border border-slate-200 bg-white px-3">
          {timing.first_call_started_at ? (
            <PipelineRow
              label="Call started"
              value={formatPipelineTimestamp(timing.first_call_started_at)}
            />
          ) : null}
          <PipelineRow
            label="Incident created"
            value={formatPipelineTimestamp(timing.incident_created_at)}
          />
          <PipelineRow
            label="First agency assigned"
            value={formatPipelineTimestamp(timing.first_agency_joined_at)}
          />
          <PipelineRow
            label="First unit assigned"
            value={formatPipelineTimestamp(timing.first_unit_assigned_at)}
          />
          <PipelineRow
            label="First unit dispatched"
            value={formatPipelineTimestamp(timing.first_unit_dispatched_at)}
          />
          <PipelineRow
            label="First unit arrived"
            value={formatPipelineTimestamp(timing.first_unit_arrived_at)}
          />
        </div>
      </div>
    </div>
  );
}
