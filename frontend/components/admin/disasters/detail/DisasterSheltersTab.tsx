"use client";

import { useState } from "react";
import { toast } from "sonner";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ActivateShelterModal } from "@/components/admin/disasters/detail/ActivateShelterModal";
import { ShelterManagingAgencyModal } from "@/components/admin/disasters/detail/ShelterManagingAgencyModal";
import { ShelterOccupancyModal } from "@/components/admin/disasters/detail/ShelterOccupancyModal";
import { DisasterLocationDisplay } from "@/components/admin/disasters/detail/DisasterLocationDisplay";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postDeactivateDisasterShelter } from "@/lib/disaster-operations-api";
import { isActiveDisasterActivation } from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse, DisasterShelterActivation } from "@/types/disaster-operations";
import type { AdminFacilityListItem, FacilityLocation } from "@/types/admin-facility";

type DisasterSheltersTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  facilities: AdminFacilityListItem[];
  facilityLocations: Map<string, FacilityLocation | null | undefined>;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterSheltersTab({
  disasterPublicUuid,
  dashboard,
  facilities,
  facilityLocations,
  isReadOnly,
  onRefresh,
}: DisasterSheltersTabProps) {
  const [activateOpen, setActivateOpen] = useState(false);
  const [managingShelter, setManagingShelter] =
    useState<DisasterShelterActivation | null>(null);
  const [occupancyShelter, setOccupancyShelter] =
    useState<DisasterShelterActivation | null>(null);
  const [deactivateShelter, setDeactivateShelter] =
    useState<DisasterShelterActivation | null>(null);
  const [isDeactivating, setIsDeactivating] = useState(false);
  const shelters = (dashboard.shelters ?? []).filter((s) =>
    isActiveDisasterActivation(s.activation_status),
  );

  const handleDeactivateShelter = async () => {
    if (!deactivateShelter?.shelter_activation_public_uuid) return;
    setIsDeactivating(true);
    try {
      await postDeactivateDisasterShelter(
        disasterPublicUuid,
        deactivateShelter.shelter_activation_public_uuid,
      );
      toast.success("Shelter deactivated.");
      setDeactivateShelter(null);
      await onRefresh();
    } catch (err) {
      toast.error(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to deactivate shelter.",
      );
    } finally {
      setIsDeactivating(false);
    }
  };

  return (
    <>
      <CommandSectionCard
        title="Shelters"
        headerAction={
          !isReadOnly ? (
            <Button type="button" size="sm" onClick={() => setActivateOpen(true)}>
              Activate shelters
            </Button>
          ) : undefined
        }
      >
        {shelters.length === 0 ? (
          <p className="text-sm text-slate-600">No active shelter activations.</p>
        ) : (
          <ul className="space-y-3 text-sm">
            {shelters.map((s) => {
              const location = s.facility_public_uuid
                ? facilityLocations.get(s.facility_public_uuid)
                : undefined;
              return (
                <li
                  key={s.shelter_activation_public_uuid ?? s.facility_public_uuid}
                  className="rounded-lg border border-slate-100 px-3 py-2"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-slate-900">
                        {s.facility_name ?? "Shelter facility"}
                      </p>
                      {s.activation_status ? (
                        <p className="text-xs text-slate-600">
                          {formatBadgeLabel(s.activation_status)}
                        </p>
                      ) : null}
                      {s.latest_occupancy != null ? (
                        <p className="mt-0.5 text-xs text-slate-600">
                          Occupancy: {s.latest_occupancy.toLocaleString()}
                          {s.effective_capacity != null
                            ? ` / ${s.effective_capacity.toLocaleString()} capacity`
                            : ""}
                        </p>
                      ) : null}
                      {s.managing_agency_name ? (
                        <p className="mt-0.5 text-xs text-slate-600">
                          Managing: {s.managing_agency_name}
                        </p>
                      ) : null}
                      {s.is_over_capacity ? (
                        <span className="mt-1 inline-block">
                          <Badge size="compact" tone="high">
                            Over capacity
                          </Badge>
                        </span>
                      ) : null}
                      <DisasterLocationDisplay
                        location={location}
                        className="mt-2"
                      />
                    </div>
                    {!isReadOnly && s.shelter_activation_public_uuid ? (
                      <div className="flex flex-wrap gap-1">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => setManagingShelter(s)}
                        >
                          Assign agency
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => setOccupancyShelter(s)}
                        >
                          Record occupancy
                        </Button>
                        <Button
                          type="button"
                          variant="danger"
                          size="sm"
                          onClick={() => setDeactivateShelter(s)}
                        >
                          Deactivate shelter
                        </Button>
                      </div>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </CommandSectionCard>

      <ActivateShelterModal
        open={activateOpen}
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        facilities={facilities}
        onClose={() => setActivateOpen(false)}
        onSuccess={onRefresh}
      />
      <ShelterManagingAgencyModal
        open={managingShelter != null}
        disasterPublicUuid={disasterPublicUuid}
        shelter={managingShelter}
        onClose={() => setManagingShelter(null)}
        onSuccess={onRefresh}
      />
      <ShelterOccupancyModal
        open={occupancyShelter != null}
        disasterPublicUuid={disasterPublicUuid}
        shelter={occupancyShelter}
        onClose={() => setOccupancyShelter(null)}
        onSuccess={onRefresh}
      />
      <ConfirmModal
        open={deactivateShelter != null}
        title="Deactivate shelter"
        message={`Deactivate ${deactivateShelter?.facility_name ?? "this shelter"}?`}
        confirmLabel="Deactivate"
        isLoading={isDeactivating}
        onConfirm={() => void handleDeactivateShelter()}
        onCancel={() => setDeactivateShelter(null)}
      />
    </>
  );
}
