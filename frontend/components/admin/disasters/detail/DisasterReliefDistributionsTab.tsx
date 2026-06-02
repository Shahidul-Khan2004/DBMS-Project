"use client";

import { useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Button } from "@/components/ui/Button";
import { RecordReliefDistributionModal } from "@/components/admin/disasters/detail/RecordReliefDistributionModal";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterReliefDistributionsTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterReliefDistributionsTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterReliefDistributionsTabProps) {
  const [recordOpen, setRecordOpen] = useState(false);

  return (
    <>
      <CommandSectionCard
        title="Relief Distributions"
        headerAction={
          !isReadOnly ? (
            <Button type="button" size="sm" onClick={() => setRecordOpen(true)}>
              Record distribution
            </Button>
          ) : undefined
        }
      >
        <p className="text-sm text-slate-600">
          Distribution history is not returned on the disaster dashboard. Record
          new deliveries against approved relief requests; refresh to see updated
          request statuses and hub inventory.
        </p>
      </CommandSectionCard>

      <RecordReliefDistributionModal
        open={recordOpen}
        disasterPublicUuid={disasterPublicUuid}
        reliefRequests={dashboard.relief_requests ?? []}
        reliefHubs={dashboard.relief_hubs ?? []}
        onClose={() => setRecordOpen(false)}
        onSuccess={onRefresh}
      />
    </>
  );
}
