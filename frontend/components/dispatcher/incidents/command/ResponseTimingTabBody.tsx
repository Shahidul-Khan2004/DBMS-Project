"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatResponseDurationMinutes } from "@/lib/format-response-duration";
import { mapResponseTimingLoadError } from "@/lib/incident-command-api-errors";
import { getIncidentResponseTiming } from "@/lib/operations-incident-api";
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

function ResponseTimingSkeleton() {
  return (
    <div className="space-y-5" aria-hidden>
      <div className="space-y-1">
        <div className="h-4 w-32 animate-pulse rounded bg-slate-200" />
        <div className="h-3 w-64 animate-pulse rounded bg-slate-100" />
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {Array.from({ length: 4 }).map((_, index) => (
          <div
            key={index}
            className="h-[4.25rem] animate-pulse rounded-lg border border-slate-200 bg-slate-50"
          />
        ))}
      </div>
      <div className="space-y-2">
        <div className="h-3 w-28 animate-pulse rounded bg-slate-200" />
        {Array.from({ length: 5 }).map((_, index) => (
          <div
            key={index}
            className="h-9 animate-pulse rounded bg-slate-100"
            style={{ width: `${100 - index * 4}%` }}
          />
        ))}
      </div>
    </div>
  );
}

function ResponseTimingContent({ timing }: { timing: OperationsResponseTiming }) {
  const showCallToIncident = Boolean(timing.first_call_started_at);

  return (
    <div className="space-y-5">
      <div>
        <h4 className="text-sm font-semibold text-slate-900">Response Timing</h4>
        <p className="mt-0.5 text-xs text-slate-600">
          Track first-response milestones for this incident.
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
          Response Pipeline
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

function useIncidentResponseTiming(
  incidentPublicUuid: string,
  isActive: boolean,
  opsMutationGeneration: number,
) {
  const [timing, setTiming] = useState<OperationsResponseTiming | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hasLoadedRef = useRef(false);
  const prevGenerationRef = useRef(opsMutationGeneration);

  const loadTiming = useCallback(
    async (options?: { background?: boolean }) => {
      if (!incidentPublicUuid) {
        return;
      }

      if (!options?.background) {
        setIsLoading(true);
      }
      setError(null);

      try {
        const response = await getIncidentResponseTiming(incidentPublicUuid);
        setTiming(response.timing);
        hasLoadedRef.current = true;
      } catch (err) {
        if (process.env.NODE_ENV === "development") {
          console.error("Failed to load response timing", err);
        }
        setError(mapResponseTimingLoadError(err));
      } finally {
        setIsLoading(false);
      }
    },
    [incidentPublicUuid],
  );

  useEffect(() => {
    if (!isActive || hasLoadedRef.current) {
      return;
    }
    void loadTiming();
  }, [isActive, loadTiming]);

  useEffect(() => {
    if (opsMutationGeneration === prevGenerationRef.current) {
      return;
    }
    prevGenerationRef.current = opsMutationGeneration;

    if (!hasLoadedRef.current) {
      return;
    }

    void loadTiming({ background: true });
  }, [opsMutationGeneration, loadTiming]);

  const retry = useCallback(() => {
    void loadTiming();
  }, [loadTiming]);

  const isInitialLoading = isLoading && !timing && !error;

  return {
    timing,
    error,
    isInitialLoading,
    retry,
  };
}

export function ResponseTimingTabBody({
  incidentPublicUuid,
  isActive,
  opsMutationGeneration,
}: {
  incidentPublicUuid: string;
  isActive: boolean;
  opsMutationGeneration: number;
}) {
  const { timing, error, isInitialLoading, retry } = useIncidentResponseTiming(
    incidentPublicUuid,
    isActive,
    opsMutationGeneration,
  );

  if (isInitialLoading) {
    return <ResponseTimingSkeleton />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-start gap-3 py-2">
        <p className="text-sm text-slate-700">{error}</p>
        <Button type="button" variant="secondary" size="sm" onClick={retry}>
          Retry
        </Button>
      </div>
    );
  }

  if (!timing) {
    return null;
  }

  return <ResponseTimingContent timing={timing} />;
}
