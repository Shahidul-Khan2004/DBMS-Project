"use client";

import { DISPATCHER_EMERGENCY_ALERT_PANEL_CLASSES } from "@/components/dispatcher/emergencyColors";
import { ActiveIncidentCard } from "@/components/dispatcher/incidents/ActiveIncidentCard";
import type {
  ActiveIncidentListItem,
  IncidentCardLocationState,
} from "@/components/dispatcher/incidents/types";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/StatusState";

interface ActiveIncidentsListProps {
  items: ActiveIncidentListItem[];
  getCardLocation: (publicUuid: string) => IncidentCardLocationState;
  className?: string;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  onNewIncident?: () => void;
}

function ActiveIncidentCardSkeleton() {
  return (
    <div
      className="h-[6.5rem] animate-pulse rounded-xl border border-slate-200/80 bg-white"
      aria-hidden
    />
  );
}

export function ActiveIncidentsList({
  items,
  getCardLocation,
  className = "",
  isLoading = false,
  error = null,
  onRetry,
  onNewIncident,
}: ActiveIncidentsListProps) {
  return (
    <section
      className={`flex min-h-0 flex-col ${className}`.trim()}
      aria-label="Active incidents"
    >
      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto pr-0.5 lg:min-h-0">
        {error ? (
          <div className={`rounded-2xl border p-6 text-center shadow-sm ${DISPATCHER_EMERGENCY_ALERT_PANEL_CLASSES}`}>
            <h3 className="font-semibold text-[#991B1B]">Unable to load active incidents</h3>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-[#991B1B]">
              Incident data could not be retrieved. Try again.
            </p>
            {onRetry ? (
              <div className="mt-4 flex justify-center">
                <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
                  Retry
                </Button>
              </div>
            ) : null}
          </div>
        ) : isLoading ? (
          <>
            {Array.from({ length: 4 }).map((_, index) => (
              <ActiveIncidentCardSkeleton key={index} />
            ))}
          </>
        ) : items.length === 0 ? (
          <EmptyState
            title="No active emergency incidents"
            description="There are currently no ongoing emergency incidents requiring command monitoring."
            action={
              onNewIncident ? (
                <Button type="button" variant="outline" size="sm" onClick={onNewIncident}>
                  + New Standalone Incident
                </Button>
              ) : undefined
            }
          />
        ) : (
          items.map((incident) => (
            <ActiveIncidentCard
              key={incident.publicUuid}
              incident={incident}
              locationState={getCardLocation(incident.publicUuid)}
            />
          ))
        )}
      </div>
    </section>
  );
}
