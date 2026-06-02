"use client";

import { useCallback, useMemo, useState } from "react";
import { ActivateReliefHubModal } from "@/components/admin/disasters/detail/ActivateReliefHubModal";
import { DisasterManualOverridePanel } from "@/components/admin/disasters/detail/DisasterManualOverridePanel";
import { DisasterPotentialFacilitiesPanel } from "@/components/admin/disasters/detail/DisasterPotentialFacilitiesPanel";
import { DisasterReliefHubsTab } from "@/components/admin/disasters/detail/DisasterReliefHubsTab";
import { activateDisasterReliefHub } from "@/components/admin/disasters/detail/disasterFacilityActivation";
import {
  getAffectedAdminAreaIds,
  isFacilityInAffectedArea,
  isReliefHubEligibleFacility,
} from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import { sortFacilitiesByName } from "@/components/admin/disasters/detail/disasterResourceHelpers";
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
  const [activatingFacilityUuid, setActivatingFacilityUuid] = useState<string | null>(null);

  const affectedAdminAreaIds = useMemo(
    () => getAffectedAdminAreaIds(dashboard),
    [dashboard],
  );

  const activeFacilities = useMemo(
    () => facilities.filter((f) => f.isActive),
    [facilities],
  );

  const potentialHubs = useMemo(
    () =>
      sortFacilitiesByName(
        activeFacilities.filter(
          (f) =>
            isReliefHubEligibleFacility(f) &&
            isFacilityInAffectedArea(f, affectedAdminAreaIds),
        ),
      ),
    [activeFacilities, affectedAdminAreaIds],
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

  const activateInAreaHub = useCallback(
    async (facilityPublicUuid: string) => {
      const facility = activeFacilities.find((f) => f.publicUuid === facilityPublicUuid);
      if (!facility) return;
      if (!isFacilityInAffectedArea(facility, affectedAdminAreaIds)) {
        openOverrideModal(facilityPublicUuid);
        return;
      }
      setActivatingFacilityUuid(facilityPublicUuid);
      try {
        const result = await activateDisasterReliefHub(disasterPublicUuid, {
          facilityPublicUuid,
        });
        if (!result.ok) {
          if (result.needsOverrideNote) {
            openOverrideModal(facilityPublicUuid);
            return;
          }
          if (result.alreadyActive) {
            await onRefresh();
          }
          return;
        }
        await onRefresh();
      } finally {
        setActivatingFacilityUuid(null);
      }
    },
    [
      activeFacilities,
      affectedAdminAreaIds,
      disasterPublicUuid,
      onRefresh,
      openOverrideModal,
    ],
  );

  return (
    <div className="grid min-h-0 gap-4 lg:grid-cols-1">
      <DisasterPotentialFacilitiesPanel
        title="Potential Relief Hubs in affected areas"
        facilities={potentialHubs}
        emptyPrimary="No relief hub facilities found inside affected areas."
        emptySecondary="Use Deactivated relief hubs to reactivate, or Activate relief hubs to add another facility."
        isReadOnly={isReadOnly}
        activateLabel="Activate as Relief Hub"
        onActivate={(uuid) => void activateInAreaHub(uuid)}
        isActivatingFacilityPublicUuid={activatingFacilityUuid}
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

      <DisasterReliefHubsTab
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        facilities={facilities}
        facilityLocations={facilityLocations}
        isReadOnly={isReadOnly}
        onRefresh={onRefresh}
        sectionTitle="Activated Relief Hubs"
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
