"use client";

import { DisasterAffectedAreasList } from "@/components/dispatcher/disasters/DisasterAffectedAreasList";
import { DisasterOpsCard } from "@/components/dispatcher/disasters/DisasterOpsCard";
import { EmptyState } from "@/components/ui/StatusState";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function DisasterAffectedAreaMatchGuide({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  const areas = dashboard.affected_areas ?? [];

  return (
    <DisasterOpsCard
      title="Affected Area Match Guide"
      subtitle="Reports in these areas may be disaster-related"
    >
      {areas.length === 0 ? (
        <EmptyState
          title="No affected areas recorded"
          description="Area matching will be unavailable until areas are recorded."
        />
      ) : (
        <DisasterAffectedAreasList areas={areas} compact />
      )}
    </DisasterOpsCard>
  );
}
