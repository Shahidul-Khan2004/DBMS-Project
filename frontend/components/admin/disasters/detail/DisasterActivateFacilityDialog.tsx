"use client";

import { useMemo, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { ActivateReliefHubModal } from "@/components/admin/disasters/detail/ActivateReliefHubModal";
import { ActivateShelterModal } from "@/components/admin/disasters/detail/ActivateShelterModal";
import { DisasterFacilityPicker } from "@/components/admin/disasters/detail/DisasterFacilityPicker";
import {
  activateDisasterReliefHub,
  activateDisasterShelter,
  requiresOverrideNote,
} from "@/components/admin/disasters/detail/disasterFacilityActivation";
import { getAffectedAdminAreaIds } from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import type { AdminFacilityListItem } from "@/types/admin-facility";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterActivateFacilityDialogProps = {
  mode: "shelter" | "hub";
  open: boolean;
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  facilities: AdminFacilityListItem[];
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function DisasterActivateFacilityDialog({
  mode,
  open,
  disasterPublicUuid,
  dashboard,
  facilities,
  onClose,
  onSuccess,
}: DisasterActivateFacilityDialogProps) {
  const [facilityPublicUuid, setFacilityPublicUuid] = useState("");
  const [usableCapacityOverride, setUsableCapacityOverride] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [overrideModalOpen, setOverrideModalOpen] = useState(false);
  const [overrideFacilityUuid, setOverrideFacilityUuid] = useState("");

  const activeFacilities = useMemo(
    () => facilities.filter((f) => f.isActive),
    [facilities],
  );

  const affectedAdminAreaIds = useMemo(
    () => getAffectedAdminAreaIds(dashboard),
    [dashboard],
  );

  const selectedFacility = useMemo(
    () => activeFacilities.find((f) => f.publicUuid === facilityPublicUuid) ?? null,
    [activeFacilities, facilityPublicUuid],
  );

  const needsOverride = requiresOverrideNote(selectedFacility, affectedAdminAreaIds);

  const overrideFacility = activeFacilities.find(
    (f) => f.publicUuid === overrideFacilityUuid,
  );
  const overrideFacilityLabel = overrideFacility
    ? `${overrideFacility.name} (${overrideFacility.facilityCode})`
    : "Selected facility";

  const handleClose = () => {
    setFacilityPublicUuid("");
    setUsableCapacityOverride("");
    setSubmitError(null);
    onClose();
  };

  const handleActivate = async () => {
    if (!selectedFacility) {
      setSubmitError("Select a facility.");
      return;
    }
    if (needsOverride) {
      setOverrideFacilityUuid(selectedFacility.publicUuid);
      setOverrideModalOpen(true);
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
          setOverrideFacilityUuid(selectedFacility.publicUuid);
          setOverrideModalOpen(true);
          return;
        }
        setSubmitError(result.error);
        if (result.alreadyActive) {
          await onSuccess();
        }
        return;
      }

      handleClose();
      await onSuccess();
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOverrideSuccess = async () => {
    setOverrideModalOpen(false);
    setOverrideFacilityUuid("");
    handleClose();
    await onSuccess();
  };

  if (!open && !overrideModalOpen) return null;

  const title = mode === "shelter" ? "Activate shelter" : "Activate relief hub";

  return (
    <>
      {open && !overrideModalOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
          <div className="flex max-h-[90vh] w-full max-w-lg flex-col rounded-xl border border-slate-200 bg-white shadow-xl">
            <div className="border-b border-slate-100 px-5 py-4">
              <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
              <p className="mt-0.5 text-xs text-slate-600">
                Select an eligible facility. Facilities outside affected areas require a
                written override reason.
              </p>
            </div>
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
              <DisasterFacilityPicker
                mode={mode}
                facilities={activeFacilities}
                affectedAdminAreaIds={affectedAdminAreaIds}
                selectedFacilityPublicUuid={facilityPublicUuid}
                onSelect={setFacilityPublicUuid}
                disabled={isSubmitting}
              />
              {!needsOverride && mode === "shelter" && selectedFacility ? (
                <div>
                  <FieldLabel htmlFor="dialog-shelter-capacity">
                    Usable capacity override (optional)
                  </FieldLabel>
                  <input
                    id="dialog-shelter-capacity"
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
              {submitError ? <ErrorAlert message={submitError} /> : null}
            </div>
            <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
              <Button
                type="button"
                variant="secondary"
                onClick={handleClose}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
              <Button
                type="button"
                isLoading={isSubmitting}
                disabled={isSubmitting || !facilityPublicUuid}
                onClick={() => void handleActivate()}
              >
                {needsOverride ? "Continue to override reason…" : "Activate"}
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {mode === "shelter" ? (
        <ActivateShelterModal
          open={overrideModalOpen}
          disasterPublicUuid={disasterPublicUuid}
          facilityPublicUuid={overrideFacilityUuid}
          facilityLabel={overrideFacilityLabel}
          onClose={() => {
            setOverrideModalOpen(false);
            setOverrideFacilityUuid("");
          }}
          onSuccess={handleOverrideSuccess}
        />
      ) : (
        <ActivateReliefHubModal
          open={overrideModalOpen}
          disasterPublicUuid={disasterPublicUuid}
          facilityPublicUuid={overrideFacilityUuid}
          facilityLabel={overrideFacilityLabel}
          onClose={() => {
            setOverrideModalOpen(false);
            setOverrideFacilityUuid("");
          }}
          onSuccess={handleOverrideSuccess}
        />
      )}
    </>
  );
}
