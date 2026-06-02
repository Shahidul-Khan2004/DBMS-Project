"use client";

import { useCallback, useMemo, useState } from "react";
import { ActivateShelterModal } from "@/components/admin/disasters/detail/ActivateShelterModal";
import { DisasterManualOverridePanel } from "@/components/admin/disasters/detail/DisasterManualOverridePanel";
import { DisasterPotentialFacilitiesPanel } from "@/components/admin/disasters/detail/DisasterPotentialFacilitiesPanel";
import { DisasterSheltersTab } from "@/components/admin/disasters/detail/DisasterSheltersTab";
import {
  activateDisasterShelter,
} from "@/components/admin/disasters/detail/disasterFacilityActivation";
import {
  getAffectedAdminAreaIds,
  isFacilityInAffectedArea,
  isShelterEligibleFacility,
} from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import { sortFacilitiesByName } from "@/components/admin/disasters/detail/disasterResourceHelpers";
import { isFinalizedDisasterActivation } from "@/lib/disaster-operations-format";
import type { AdminFacilityListItem, FacilityLocation } from "@/types/admin-facility";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterShelterNetworkTabProps = {
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

export function DisasterShelterNetworkTab({
  disasterPublicUuid,
  dashboard,
  facilities,
  facilityLocations,
  isReadOnly,
  onRefresh,
}: DisasterShelterNetworkTabProps) {
  const [overrideModalOpen, setOverrideModalOpen] = useState(false);
  const [overrideFacilityUuid, setOverrideFacilityUuid] = useState("");
  const [overrideShelterUuid, setOverrideShelterUuid] = useState("");
  const [activatingFacilityUuid, setActivatingFacilityUuid] = useState<string | null>(null);

  const affectedAdminAreaIds = useMemo(
    () => getAffectedAdminAreaIds(dashboard),
    [dashboard],
  );

  const activeFacilities = useMemo(
    () => facilities.filter((f) => f.isActive),
    [facilities],
  );

  const potentialShelters = useMemo(
    () =>
      sortFacilitiesByName(
        activeFacilities.filter(
          (f) =>
            isShelterEligibleFacility(f) &&
            isFacilityInAffectedArea(f, affectedAdminAreaIds),
        ),
      ),
    [activeFacilities, affectedAdminAreaIds],
  );

  const deactivatedShelterFacilityUuids = useMemo(() => {
    const ids = new Set<string>();
    for (const shelter of dashboard.shelters ?? []) {
      if (
        isFinalizedDisasterActivation(shelter.activation_status) &&
        shelter.facility_public_uuid
      ) {
        ids.add(shelter.facility_public_uuid);
      }
    }
    return ids;
  }, [dashboard.shelters]);

  const openOverrideModal = useCallback((facilityPublicUuid: string) => {
    setOverrideFacilityUuid(facilityPublicUuid);
    setOverrideModalOpen(true);
  }, []);

  const closeOverrideModal = useCallback(() => {
    setOverrideModalOpen(false);
    setOverrideFacilityUuid("");
  }, []);

  const activateInAreaShelter = useCallback(
    async (facilityPublicUuid: string) => {
      const facility = activeFacilities.find((f) => f.publicUuid === facilityPublicUuid);
      if (!facility) return;
      if (!isFacilityInAffectedArea(facility, affectedAdminAreaIds)) {
        openOverrideModal(facilityPublicUuid);
        return;
      }
      setActivatingFacilityUuid(facilityPublicUuid);
      try {
        const result = await activateDisasterShelter(disasterPublicUuid, {
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
        title="Potential Shelters in affected areas"
        facilities={potentialShelters}
        emptyPrimary="No shelter facilities found inside affected areas."
        emptySecondary="Use Deactivated shelters to reactivate, or Activate shelters to add another facility."
        isReadOnly={isReadOnly}
        activateLabel="Activate as Shelter"
        onActivate={(uuid) => void activateInAreaShelter(uuid)}
        isActivatingFacilityPublicUuid={activatingFacilityUuid}
      />

      <DisasterManualOverridePanel
        mode="shelter"
        disasterPublicUuid={disasterPublicUuid}
        facilities={activeFacilities}
        affectedAdminAreaIds={affectedAdminAreaIds}
        allowedFacilityPublicUuids={deactivatedShelterFacilityUuids}
        selectedFacilityPublicUuid={overrideShelterUuid}
        onSelect={setOverrideShelterUuid}
        onRequestOverrideModal={openOverrideModal}
        onSuccess={onRefresh}
        isReadOnly={isReadOnly}
      />

      <DisasterSheltersTab
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        facilities={facilities}
        facilityLocations={facilityLocations}
        isReadOnly={isReadOnly}
        onRefresh={onRefresh}
        sectionTitle="Activated Shelters"
      />

      <ActivateShelterModal
        open={overrideModalOpen}
        disasterPublicUuid={disasterPublicUuid}
        facilityPublicUuid={overrideFacilityUuid}
        facilityLabel={formatFacilityLabel(facilities, overrideFacilityUuid)}
        onClose={closeOverrideModal}
        onSuccess={async () => {
          setOverrideShelterUuid("");
          await onRefresh();
        }}
      />
    </div>
  );
}
