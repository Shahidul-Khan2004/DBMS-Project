import { ApiError, getApiErrorMessage } from "@/lib/api";
import { linkIncidentToDisaster } from "@/lib/disaster-operations-api";

export type LinkIncidentToDisasterResult =
  | { ok: true }
  | { ok: false; message: string; status?: number };

export async function submitLinkIncidentToDisaster(
  disasterPublicUuid: string,
  incidentPublicUuid: string,
): Promise<LinkIncidentToDisasterResult> {
  try {
    await linkIncidentToDisaster(disasterPublicUuid, incidentPublicUuid);
    return { ok: true };
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      return {
        ok: false,
        status: 409,
        message: "This incident may already be linked to this disaster.",
      };
    }
    return {
      ok: false,
      message:
        err instanceof ApiError
          ? getApiErrorMessage(err, "Failed to link incident to disaster.")
          : "Failed to link incident to disaster.",
    };
  }
}
