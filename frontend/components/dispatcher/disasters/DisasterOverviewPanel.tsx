"use client";

import { useState } from "react";
import { DisasterAgencyResourcesDialog } from "@/components/dispatcher/disasters/DisasterAgencyResourcesDialog";
import { DisasterOverviewSectionCard } from "@/components/dispatcher/disasters/DisasterOverviewSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
  getActiveDisasterReliefHubs,
  getActiveDisasterShelters,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function DisasterOverviewPanel({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  const [resourcesOpen, setResourcesOpen] = useState(false);
  const { disaster } = dashboard;
  const shelters = getActiveDisasterShelters(dashboard.shelters ?? []);
  const reliefHubs = getActiveDisasterReliefHubs(dashboard.relief_hubs ?? []);
  const reliefRequests = dashboard.relief_requests ?? [];

  return (
    <>
      <DisasterOverviewSectionCard
        title="Disaster Overview"
        className="shrink-0"
      >
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs font-medium text-slate-500">Event code</dt>
          <dd className="mt-0.5 font-medium text-slate-900">{disaster.event_code}</dd>
        </div>
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
          <dt className="text-xs font-medium text-slate-500">Type</dt>
          <dd className="mt-0.5 text-slate-900">
            {formatDisasterEventTypeLabel(
              disaster.event_type_code,
              disaster.event_type_name,
            )}
          </dd>
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
        <div className="sm:col-span-2">
          <dt className="text-xs font-medium text-slate-500">Title</dt>
          <dd className="mt-0.5 font-semibold text-slate-900">{disaster.title}</dd>
        </div>
        {disaster.public_guidance ? (
          <div className="sm:col-span-2">
            <dt className="text-xs font-medium text-slate-500">Public guidance</dt>
            <dd className="mt-0.5 text-slate-700">{disaster.public_guidance}</dd>
          </div>
        ) : null}
        </dl>

        <div className="mt-4 border-t border-slate-100 pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-sm font-semibold text-slate-900">Agency Resources</p>
              <p className="text-xs text-slate-600">
                Shelters {shelters.length} · Relief hubs {reliefHubs.length} · Relief
                requests {reliefRequests.length}
              </p>
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => setResourcesOpen(true)}
            >
              View details
            </Button>
          </div>
        </div>
      </DisasterOverviewSectionCard>

      <DisasterAgencyResourcesDialog
        open={resourcesOpen}
        dashboard={dashboard}
        onClose={() => setResourcesOpen(false)}
      />
    </>
  );
}
