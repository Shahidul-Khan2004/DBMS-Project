"use client";

import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { getDispatcherClickableInsetRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/StatusState";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatIncidentStatus } from "@/lib/incident-status";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function DisasterLinkedIncidentsPanel({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  const incidents = dashboard.linked_incidents ?? [];

  return (
    <CommandSectionCard
      title="Linked Incidents"
      subtitle={`${incidents.length} incident${incidents.length === 1 ? "" : "s"}`}
      scrollableBody={incidents.length > 4}
      fillHeight={incidents.length > 4}
    >
      {incidents.length === 0 ? (
        <EmptyState
          title="No linked incidents"
          description="Emergency incidents linked to this disaster will appear here."
        />
      ) : (
        <ul className="space-y-2">
          {incidents.map((incident) => {
            const uuid = incident.incident_public_uuid;
            if (!uuid) return null;

            return (
              <li key={uuid}>
                <Link
                  href={`/dashboard/dispatcher/incidents/${encodeURIComponent(uuid)}`}
                  className={`group flex items-center justify-between gap-3 rounded-lg border px-3 py-2 ${getDispatcherClickableInsetRowClasses()}`}
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-slate-900">
                      {incident.title ?? "Untitled incident"}
                    </p>
                    <p className="mt-0.5 text-xs text-slate-600">
                      {incident.incident_code ?? "—"}
                      {incident.location_upazila_name
                        ? ` · ${incident.location_upazila_name}`
                        : ""}
                      {incident.linked_at
                        ? ` · Linked ${formatBangladeshTime(incident.linked_at)}`
                        : ""}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {incident.incident_status ? (
                      <Badge size="compact" tone={incident.incident_status}>
                        {formatBadgeLabel(
                          formatIncidentStatus(incident.incident_status),
                        )}
                      </Badge>
                    ) : null}
                    {incident.distance_km != null ? (
                      <span className="text-xs text-slate-500">
                        {incident.distance_km.toFixed(1)} km
                      </span>
                    ) : null}
                    <ChevronRight
                      className="h-4 w-4 text-[#002D62] transition-transform group-hover:translate-x-0.5"
                      aria-hidden
                    />
                  </div>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </CommandSectionCard>
  );
}
