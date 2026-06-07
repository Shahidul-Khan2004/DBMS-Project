"use client";

import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/StatusState";
import {
  formatReliefRequestStatusLabel,
  getActiveDisasterReliefHubs,
  getActiveDisasterShelters,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function DisasterResponseResourcesPanel({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  const shelters = getActiveDisasterShelters(dashboard.shelters ?? []);
  const reliefHubs = getActiveDisasterReliefHubs(dashboard.relief_hubs ?? []);
  const reliefRequests = dashboard.relief_requests ?? [];
  const hasResources =
    shelters.length > 0 || reliefHubs.length > 0 || reliefRequests.length > 0;

  return (
    <CommandSectionCard
      title="Response Resources"
      subtitle="Read-only shelter, hub, and relief summaries"
      scrollableBody
      fillHeight
    >
      {!hasResources ? (
        <EmptyState
          title="No response resources"
          description="Activated shelters, relief hubs, and requests will appear here."
        />
      ) : (
        <div className="space-y-4">
          <section>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Shelters ({shelters.length})
            </h4>
            {shelters.length === 0 ? (
              <p className="mt-1 text-xs text-slate-500">No active shelters.</p>
            ) : (
              <ul className="mt-2 space-y-1.5">
                {shelters.map((shelter) => (
                  <li
                    key={
                      shelter.shelter_activation_public_uuid ??
                      shelter.facility_public_uuid
                    }
                    className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 text-sm"
                  >
                    <p className="font-medium text-slate-900">
                      {shelter.facility_name ?? "Shelter"}
                    </p>
                    <p className="mt-0.5 text-xs text-slate-600">
                      {shelter.latest_occupancy != null
                        ? `Occupancy: ${shelter.latest_occupancy}`
                        : "Occupancy not recorded"}
                      {shelter.effective_capacity != null
                        ? ` / ${shelter.effective_capacity} capacity`
                        : ""}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Relief Hubs ({reliefHubs.length})
            </h4>
            {reliefHubs.length === 0 ? (
              <p className="mt-1 text-xs text-slate-500">No active relief hubs.</p>
            ) : (
              <ul className="mt-2 space-y-1.5">
                {reliefHubs.map((hub) => (
                  <li
                    key={hub.relief_hub_public_uuid ?? hub.facility_public_uuid}
                    className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 text-sm"
                  >
                    <p className="font-medium text-slate-900">
                      {hub.facility_name ?? "Relief hub"}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Relief Requests ({reliefRequests.length})
            </h4>
            {reliefRequests.length === 0 ? (
              <p className="mt-1 text-xs text-slate-500">No relief requests.</p>
            ) : (
              <ul className="mt-2 space-y-1.5">
                {reliefRequests.map((request) => (
                  <li
                    key={request.relief_request_public_uuid}
                    className="flex items-center justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 text-sm"
                  >
                    <span className="min-w-0 truncate font-medium text-slate-900">
                      {request.request_code ?? "Relief request"}
                    </span>
                    <Badge size="compact" tone="neutral">
                      {formatBadgeLabel(
                        formatReliefRequestStatusLabel(request.status_code),
                      )}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </CommandSectionCard>
  );
}
