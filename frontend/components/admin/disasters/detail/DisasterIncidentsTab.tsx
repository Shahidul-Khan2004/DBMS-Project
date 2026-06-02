"use client";

import { useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { LinkIncidentModal } from "@/components/admin/disasters/detail/LinkIncidentModal";
import { UnlinkIncidentModal } from "@/components/admin/disasters/detail/UnlinkIncidentModal";
import type {
  DisasterDashboardResponse,
  DisasterLinkedIncident,
} from "@/types/disaster-operations";
import { formatBangladeshTime } from "@/lib/datetime";

type DisasterIncidentsTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterIncidentsTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterIncidentsTabProps) {
  const [linkOpen, setLinkOpen] = useState(false);
  const [unlinkTarget, setUnlinkTarget] = useState<DisasterLinkedIncident | null>(
    null,
  );
  const incidents = dashboard.linked_incidents ?? [];

  return (
    <>
      <CommandSectionCard
        title="Linked Incidents"
        headerAction={
          !isReadOnly ? (
            <Button type="button" size="sm" onClick={() => setLinkOpen(true)}>
              Link incident
            </Button>
          ) : undefined
        }
      >
        {incidents.length === 0 ? (
          <p className="text-sm text-slate-600">No incidents linked to this disaster.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {incidents.map((inc) => (
              <li
                key={inc.incident_public_uuid}
                className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-slate-100 px-3 py-2"
              >
                <div>
                  <p className="font-medium text-slate-900">
                    {inc.title ?? "Incident"}
                  </p>
                  <p className="text-xs text-slate-600">
                    {inc.incident_code}
                    {inc.incident_status
                      ? ` · ${formatBadgeLabel(inc.incident_status)}`
                      : ""}
                  </p>
                  {inc.location_upazila_name ? (
                    <p className="mt-0.5 text-xs text-slate-500">
                      {inc.location_upazila_name}
                    </p>
                  ) : null}
                  {inc.linked_at ? (
                    <p className="mt-0.5 text-xs text-slate-500">
                      Linked {formatBangladeshTime(inc.linked_at)}
                    </p>
                  ) : null}
                  {inc.link_note ? (
                    <p className="mt-1 text-xs text-slate-500">{inc.link_note}</p>
                  ) : null}
                </div>
                {!isReadOnly ? (
                  <Button
                    type="button"
                    variant="danger"
                    size="sm"
                    onClick={() => setUnlinkTarget(inc)}
                  >
                    Unlink
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <LinkIncidentModal
        open={linkOpen}
        disasterPublicUuid={disasterPublicUuid}
        onClose={() => setLinkOpen(false)}
        onSuccess={onRefresh}
      />

      <UnlinkIncidentModal
        open={unlinkTarget != null}
        disasterPublicUuid={disasterPublicUuid}
        incident={unlinkTarget}
        onClose={() => setUnlinkTarget(null)}
        onSuccess={onRefresh}
      />
    </>
  );
}
