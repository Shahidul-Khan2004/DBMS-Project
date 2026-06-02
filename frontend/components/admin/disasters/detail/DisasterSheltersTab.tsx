"use client";

import { useState } from "react";
import { toast } from "sonner";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { DisasterActivateFacilityDialog } from "@/components/admin/disasters/detail/DisasterActivateFacilityDialog";
import { ShelterManagingAgencyModal } from "@/components/admin/disasters/detail/ShelterManagingAgencyModal";
import { ShelterOccupancyModal } from "@/components/admin/disasters/detail/ShelterOccupancyModal";
import { DisasterLocationDisplay } from "@/components/admin/disasters/detail/DisasterLocationDisplay";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postDeactivateDisasterShelter } from "@/lib/disaster-operations-api";
import { getActiveDisasterShelters } from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse, DisasterShelterActivation } from "@/types/disaster-operations";
import type { AdminFacilityListItem, FacilityLocation } from "@/types/admin-facility";

type DisasterSheltersTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  facilities: AdminFacilityListItem[];
  facilityLocations: Map<string, FacilityLocation | null | undefined>;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
  sectionTitle?: string;
  hideListActivateAction?: boolean;
  suppressActivateModal?: boolean;
  emptyMessage?: string;
};

export function DisasterSheltersTab({
  disasterPublicUuid,
  dashboard,
  facilities,
  facilityLocations,
  isReadOnly,
  onRefresh,
  sectionTitle = "Shelters",
  hideListActivateAction = false,
  suppressActivateModal = false,
  emptyMessage,
}: DisasterSheltersTabProps) {
  const [activateOpen, setActivateOpen] = useState(false);
  const [managingShelter, setManagingShelter] =
    useState<DisasterShelterActivation | null>(null);
  const [occupancyShelter, setOccupancyShelter] =
    useState<DisasterShelterActivation | null>(null);
  const [deactivateShelter, setDeactivateShelter] =
    useState<DisasterShelterActivation | null>(null);
  const [isDeactivating, setIsDeactivating] = useState(false);

  const activeShelters = getActiveDisasterShelters(dashboard.shelters ?? []);

  const resolvedEmptyMessage =
    emptyMessage ??
    "No active shelters. Reactivate a deactivated shelter above, or use Activate shelters to add one.";

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

  const renderShelterRow = (s: DisasterShelterActivation) => {
    const location = s.facility_public_uuid
      ? facilityLocations.get(s.facility_public_uuid)
      : undefined;

    return (
      <li
        key={s.shelter_activation_public_uuid ?? s.facility_public_uuid}
        className="rounded-lg border border-slate-100 px-3 py-2.5"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1 space-y-0.5">
            <p className="font-medium text-slate-900">
              {s.facility_name ?? "Shelter facility"}
            </p>
            {s.activation_status ? (
              <p className="text-xs text-slate-600">
                {formatBadgeLabel(s.activation_status)}
              </p>
            ) : null}
            {s.latest_occupancy != null ? (
              <p className="text-xs text-slate-600">
                Occupancy: {s.latest_occupancy.toLocaleString()}
                {s.effective_capacity != null
                  ? ` / ${s.effective_capacity.toLocaleString()} capacity`
                  : ""}
              </p>
            ) : null}
            {s.managing_agency_name ? (
              <p className="text-xs text-slate-600">
                Managing: {s.managing_agency_name}
              </p>
            ) : null}
            {s.is_over_capacity ? (
              <Badge size="compact" tone="high">
                Over capacity
              </Badge>
            ) : null}
            <DisasterLocationDisplay location={location} className="mt-1" compact />
          </div>
          {!isReadOnly && s.shelter_activation_public_uuid ? (
            <div className="flex shrink-0 flex-col gap-1 sm:flex-row sm:flex-wrap">
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
  };

  return (
    <>
      <CommandSectionCard
        title={sectionTitle}
        headerAction={
          !isReadOnly && !hideListActivateAction ? (
            <Button type="button" size="sm" onClick={() => setActivateOpen(true)}>
              Activate shelters
            </Button>
          ) : undefined
        }
      >
        {activeShelters.length === 0 ? (
          <p className="text-sm text-slate-600">{resolvedEmptyMessage}</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {activeShelters.map((s) => renderShelterRow(s))}
          </ul>
        )}
      </CommandSectionCard>

      {!suppressActivateModal ? (
        <DisasterActivateFacilityDialog
          mode="shelter"
          open={activateOpen}
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          facilities={facilities}
          onClose={() => setActivateOpen(false)}
          onSuccess={onRefresh}
        />
      ) : null}

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
