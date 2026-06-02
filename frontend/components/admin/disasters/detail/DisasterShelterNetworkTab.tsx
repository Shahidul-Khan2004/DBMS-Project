"use client";

import { useCallback, useMemo, useState } from "react";
import { ActivateShelterModal } from "@/components/admin/disasters/detail/ActivateShelterModal";
import { DisasterManualOverridePanel } from "@/components/admin/disasters/detail/DisasterManualOverridePanel";
import { DisasterSheltersTab } from "@/components/admin/disasters/detail/DisasterSheltersTab";
import { getAffectedAdminAreaIds } from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
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

  const affectedAdminAreaIds = useMemo(
    () => getAffectedAdminAreaIds(dashboard),
    [dashboard],
  );

  const activeFacilities = useMemo(
    () => facilities.filter((f) => f.isActive),
    [facilities],
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

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <DisasterSheltersTab
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        facilities={facilities}
        facilityLocations={facilityLocations}
        isReadOnly={isReadOnly}
        onRefresh={onRefresh}
        sectionTitle="Activated Shelters"
        embeddedInPanel
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
