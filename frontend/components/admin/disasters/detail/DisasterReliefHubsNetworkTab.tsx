"use client";

import { useCallback, useMemo, useState } from "react";
import { ActivateReliefHubModal } from "@/components/admin/disasters/detail/ActivateReliefHubModal";
import { DisasterManualOverridePanel } from "@/components/admin/disasters/detail/DisasterManualOverridePanel";
import { DisasterReliefHubsTab } from "@/components/admin/disasters/detail/DisasterReliefHubsTab";
import { getAffectedAdminAreaIds } from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import { isFinalizedDisasterActivation } from "@/lib/disaster-operations-format";
import type { AdminFacilityListItem, FacilityLocation } from "@/types/admin-facility";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterReliefHubsNetworkTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  facilities: AdminFacilityListItem[];
  facilityLocations: Map<string, FacilityLocation | null | undefined>;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

function formatFacilityLabel(
  facilities: AdminFacilityListItem[],
  facilityPublicUuid: string,
): string {
  const facility = facilities.find((f) => f.publicUuid === facilityPublicUuid);
  if (!facility) return "Selected facility";
  return `${facility.name} (${facility.facilityCode})`;
}

export function DisasterReliefHubsNetworkTab({
  disasterPublicUuid,
  dashboard,
  facilities,
  facilityLocations,
  isReadOnly,
  onRefresh,
}: DisasterReliefHubsNetworkTabProps) {
  const [overrideModalOpen, setOverrideModalOpen] = useState(false);
  const [overrideFacilityUuid, setOverrideFacilityUuid] = useState("");
  const [overrideHubUuid, setOverrideHubUuid] = useState("");

  const affectedAdminAreaIds = useMemo(
    () => getAffectedAdminAreaIds(dashboard),
    [dashboard],
  );

  const activeFacilities = useMemo(
    () => facilities.filter((f) => f.isActive),
    [facilities],
  );

  const deactivatedHubFacilityUuids = useMemo(() => {
    const ids = new Set<string>();
    for (const hub of dashboard.relief_hubs ?? []) {
      if (
        isFinalizedDisasterActivation(hub.activation_status) &&
        hub.facility_public_uuid
      ) {
        ids.add(hub.facility_public_uuid);
      }
    }
    return ids;
  }, [dashboard.relief_hubs]);

  const openOverrideModal = useCallback((facilityPublicUuid: string) => {
    setOverrideFacilityUuid(facilityPublicUuid);
    setOverrideModalOpen(true);
  }, []);

  const closeOverrideModal = useCallback(() => {
    setOverrideModalOpen(false);
    setOverrideFacilityUuid("");
  }, []);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <DisasterReliefHubsTab
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        facilities={facilities}
        facilityLocations={facilityLocations}
        isReadOnly={isReadOnly}
        onRefresh={onRefresh}
        sectionTitle="Activated Relief Hubs"
        embeddedInPanel
      />

      <DisasterManualOverridePanel
        mode="hub"
        disasterPublicUuid={disasterPublicUuid}
        facilities={activeFacilities}
        affectedAdminAreaIds={affectedAdminAreaIds}
        allowedFacilityPublicUuids={deactivatedHubFacilityUuids}
        selectedFacilityPublicUuid={overrideHubUuid}
        onSelect={setOverrideHubUuid}
        onRequestOverrideModal={openOverrideModal}
        onSuccess={onRefresh}
        isReadOnly={isReadOnly}
      />

      <ActivateReliefHubModal
        open={overrideModalOpen}
        disasterPublicUuid={disasterPublicUuid}
        facilityPublicUuid={overrideFacilityUuid}
        facilityLabel={formatFacilityLabel(facilities, overrideFacilityUuid)}
        onClose={closeOverrideModal}
        onSuccess={async () => {
          setOverrideHubUuid("");
          await onRefresh();
        }}
      />
    </div>
  );
}
