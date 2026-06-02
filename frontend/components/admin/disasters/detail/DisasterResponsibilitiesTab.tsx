"use client";

import { useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { AssignResponsibilityModal } from "@/components/admin/disasters/detail/AssignResponsibilityModal";
import { formatResponsibilityTypeLabel } from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterResponsibilitiesTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterResponsibilitiesTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterResponsibilitiesTabProps) {
  const [assignOpen, setAssignOpen] = useState(false);
  const responsibilities = dashboard.responsibilities ?? [];

  return (
    <>
      <CommandSectionCard
        title="Responsibilities"
        headerAction={
          !isReadOnly ? (
            <Button type="button" size="sm" onClick={() => setAssignOpen(true)}>
              Assign responsibility
            </Button>
          ) : undefined
        }
      >
        {responsibilities.length === 0 ? (
          <p className="text-sm text-slate-600">No agency responsibilities assigned.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {responsibilities.map((r) => (
              <li
                key={`${r.agency_public_uuid}-${r.responsibility_type}`}
                className="rounded-lg border border-slate-100 px-3 py-2"
              >
                <span className="font-medium text-slate-900">
                  {r.agency_name ?? "Agency"}
                </span>
                <span className="text-slate-600">
                  {" "}
                  · {formatResponsibilityTypeLabel(r.responsibility_type)}
                </span>
                {r.is_lead ? (
                  <span className="ml-2 inline-block">
                    <Badge size="compact">Lead</Badge>
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <AssignResponsibilityModal
        open={assignOpen}
        disasterPublicUuid={disasterPublicUuid}
        onClose={() => setAssignOpen(false)}
        onSuccess={onRefresh}
      />
    </>
  );
}
