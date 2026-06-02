"use client";

import { useMemo, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { DisasterFacilityPicker } from "@/components/admin/disasters/detail/DisasterFacilityPicker";
import {
  activateDisasterReliefHub,
  activateDisasterShelter,
  requiresOverrideNote,
} from "@/components/admin/disasters/detail/disasterFacilityActivation";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import type { AdminFacilityListItem } from "@/types/admin-facility";

type DisasterManualOverridePanelProps = {
  mode: "shelter" | "hub";
  disasterPublicUuid: string;
  facilities: AdminFacilityListItem[];
  affectedAdminAreaIds: Set<number>;
  allowedFacilityPublicUuids: ReadonlySet<string>;
  selectedFacilityPublicUuid: string;
  onSelect: (facilityPublicUuid: string) => void;
  onRequestOverrideModal: (facilityPublicUuid: string) => void;
  onSuccess: () => Promise<void>;
  isReadOnly: boolean;
};

export function DisasterManualOverridePanel({
  mode,
  disasterPublicUuid,
  facilities,
  affectedAdminAreaIds,
  allowedFacilityPublicUuids,
  selectedFacilityPublicUuid,
  onSelect,
  onRequestOverrideModal,
  onSuccess,
  isReadOnly,
}: DisasterManualOverridePanelProps) {
  const [usableCapacityOverride, setUsableCapacityOverride] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const selectedFacility = useMemo(
    () => facilities.find((f) => f.publicUuid === selectedFacilityPublicUuid) ?? null,
    [facilities, selectedFacilityPublicUuid],
  );

  const needsOverride = requiresOverrideNote(selectedFacility, affectedAdminAreaIds);

  if (isReadOnly || allowedFacilityPublicUuids.size === 0) return null;

  const handleReactivate = async () => {
    if (!selectedFacility) {
      setSubmitError("Select a facility.");
      return;
    }
    if (needsOverride) {
      onRequestOverrideModal(selectedFacility.publicUuid);
      return;
    }

    let capacity: number | undefined;
    if (mode === "shelter" && usableCapacityOverride.trim()) {
      const parsed = Number.parseInt(usableCapacityOverride.trim(), 10);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        setSubmitError("Usable capacity override must be a positive whole number.");
        return;
      }
      capacity = parsed;
    }

    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const result =
        mode === "shelter"
          ? await activateDisasterShelter(disasterPublicUuid, {
              facilityPublicUuid: selectedFacility.publicUuid,
              ...(capacity != null ? { usableCapacityOverride: capacity } : {}),
            })
          : await activateDisasterReliefHub(disasterPublicUuid, {
              facilityPublicUuid: selectedFacility.publicUuid,
            });

      if (!result.ok) {
        if (result.needsOverrideNote) {
          onRequestOverrideModal(selectedFacility.publicUuid);
          return;
        }
        setSubmitError(result.error);
        if (result.alreadyActive) {
          await onSuccess();
        }
        return;
      }

      setUsableCapacityOverride("");
      onSelect("");
      await onSuccess();
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <CommandSectionCard
      title={mode === "shelter" ? "Deactivated shelters" : "Deactivated relief hubs"}
    >
      <DisasterFacilityPicker
        mode={mode}
        facilities={facilities}
        affectedAdminAreaIds={affectedAdminAreaIds}
        selectedFacilityPublicUuid={selectedFacilityPublicUuid}
        onSelect={onSelect}
        disabled={isSubmitting}
        overrideOnly
        allowedFacilityPublicUuids={allowedFacilityPublicUuids}
      />
      {selectedFacility ? (
        <p className="mt-2 text-sm text-slate-700">
          Selected:{" "}
          <span className="font-medium text-slate-900">{selectedFacility.name}</span>
          <span className="text-slate-500"> ({selectedFacility.facilityCode})</span>
          {needsOverride ? (
            <span className="ml-1 text-xs text-amber-700">— outside affected area</span>
          ) : (
            <span className="ml-1 text-xs text-emerald-700">— in affected area</span>
          )}
        </p>
      ) : null}
      {!needsOverride && mode === "shelter" && selectedFacility ? (
        <div className="mt-3">
          <FieldLabel htmlFor="shelter-capacity-override">
            Usable capacity override (optional)
          </FieldLabel>
          <input
            id="shelter-capacity-override"
            type="number"
            min={1}
            step={1}
            value={usableCapacityOverride}
            onChange={(e) => setUsableCapacityOverride(e.target.value)}
            disabled={isSubmitting}
            placeholder="Leave blank to use facility default"
            className={`${triageFieldClassName} mt-1`}
          />
        </div>
      ) : null}
      {submitError ? (
        <div className="mt-2">
          <ErrorAlert message={submitError} />
        </div>
      ) : null}
      <Button
        type="button"
        size="sm"
        className="mt-2"
        disabled={!selectedFacilityPublicUuid || isSubmitting}
        isLoading={isSubmitting}
        onClick={() => void handleReactivate()}
      >
        {needsOverride ? "Continue to override reason…" : "Reactivate"}
      </Button>
    </CommandSectionCard>
  );
}
