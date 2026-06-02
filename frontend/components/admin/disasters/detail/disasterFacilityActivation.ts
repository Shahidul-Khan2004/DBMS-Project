import { toast } from "sonner";
import {
  isFacilityInAffectedArea,
} from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import {
  postActivateDisasterReliefHub,
  postActivateDisasterShelter,
} from "@/lib/disaster-operations-api";
import type { AdminFacilityListItem } from "@/types/admin-facility";
import type {
  ActivateReliefHubPayload,
  ActivateShelterPayload,
} from "@/types/disaster-operations";

export const MANUAL_ACTIVATION_NOTE_REQUIRED = "MANUAL_ACTIVATION_NOTE_REQUIRED";

export function requiresOverrideNote(
  facility: AdminFacilityListItem | null | undefined,
  affectedAdminAreaIds: Set<number>,
): boolean {
  if (!facility) return true;
  return !isFacilityInAffectedArea(facility, affectedAdminAreaIds);
}

export function isManualActivationNoteRequiredError(err: unknown): boolean {
  return err instanceof ApiError && err.code === MANUAL_ACTIVATION_NOTE_REQUIRED;
}

export type ActivateShelterOptions = ActivateShelterPayload;

export type ActivateReliefHubOptions = ActivateReliefHubPayload;

export type FacilityActivationResult =
  | { ok: true; reactivated?: boolean }
  | {
      ok: false;
      error: string;
      needsOverrideNote?: boolean;
      alreadyActive?: boolean;
    };

export async function activateDisasterShelter(
  disasterPublicUuid: string,
  options: ActivateShelterOptions,
): Promise<FacilityActivationResult> {
  try {
    await postActivateDisasterShelter(disasterPublicUuid, options);
    toast.success("Shelter activated.");
    return { ok: true };
  } catch (err) {
    const message =
      err instanceof ApiError
        ? getApiErrorMessage(err, err.message)
        : "Failed to activate shelter.";
    if (isManualActivationNoteRequiredError(err)) {
      return { ok: false, error: message, needsOverrideNote: true };
    }
    if (err instanceof ApiError && err.code === "SHELTER_ALREADY_ACTIVATED") {
      return {
        ok: false,
        error:
          "This shelter is already active for this disaster. It should appear in Activated Shelters below.",
        alreadyActive: true,
      };
    }
    toast.error(message);
    return { ok: false, error: message };
  }
}

export async function activateDisasterReliefHub(
  disasterPublicUuid: string,
  options: ActivateReliefHubOptions,
): Promise<FacilityActivationResult> {
  try {
    await postActivateDisasterReliefHub(disasterPublicUuid, options);
    toast.success("Relief hub activated.");
    return { ok: true };
  } catch (err) {
    const message =
      err instanceof ApiError
        ? getApiErrorMessage(err, err.message)
        : "Failed to activate relief hub.";
    if (isManualActivationNoteRequiredError(err)) {
      return { ok: false, error: message, needsOverrideNote: true };
    }
    if (err instanceof ApiError && err.code === "RELIEF_HUB_ALREADY_ACTIVATED") {
      return {
        ok: false,
        error:
          "This relief hub is already active for this disaster. It should appear in Activated Relief Hubs below.",
        alreadyActive: true,
      };
    }
    toast.error(message);
    return { ok: false, error: message };
  }
}
