"use client";

import { DisasterAffectedAreasList } from "@/components/dispatcher/disasters/DisasterAffectedAreasList";
import { DisasterOverviewSectionCard } from "@/components/dispatcher/disasters/DisasterOverviewSectionCard";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/StatusState";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function DisasterAffectedAreasPanel({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  const areas = dashboard.affected_areas ?? [];

  return (
    <DisasterOverviewSectionCard
      title="Affected Areas"
      className="min-h-0 h-full"
      scrollBody
      right={
        areas.length > 0 ? (
          <Badge size="compact" tone="neutral">
            {areas.length} area{areas.length === 1 ? "" : "s"}
          </Badge>
        ) : null
      }
    >
      {areas.length === 0 ? (
        <EmptyState
          title="No affected areas recorded"
          description="Affected upazilas will appear here when recorded by System Admin."
        />
      ) : (
        <DisasterAffectedAreasList areas={areas} />
      )}
    </DisasterOverviewSectionCard>
  );
}
