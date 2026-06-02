"use client";

import { DisasterReliefDistributionsTab } from "@/components/admin/disasters/detail/DisasterReliefDistributionsTab";
import { DisasterReliefRequestsTab } from "@/components/admin/disasters/detail/DisasterReliefRequestsTab";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterReliefTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterReliefTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterReliefTabProps) {
  return (
    <div className="space-y-6">
      <DisasterReliefRequestsTab
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        isReadOnly={isReadOnly}
        onRefresh={onRefresh}
      />
      <DisasterReliefDistributionsTab
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        isReadOnly={isReadOnly}
        onRefresh={onRefresh}
      />
    </div>
  );
}
