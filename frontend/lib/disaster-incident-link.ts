import { ApiError } from "@/lib/api";
import { linkIncidentToDisaster } from "@/lib/disaster-operations-api";

export type TryLinkIncidentResult =
  | { ok: true }
  | { ok: false; message: string };

export type TryLinkIncidentContext = "created" | "linked";

function getLinkFailureMessage(context: TryLinkIncidentContext): string {
  const prefix =
    context === "linked"
      ? "Incident linked, but disaster link failed."
      : "Incident created, but disaster link failed.";
  return `${prefix} You can attach it from Incident Command.`;
}

export async function tryLinkIncidentToDisaster({
  disasterUuid,
  incidentUuid,
  context = "created",
}: {
  disasterUuid: string;
  incidentUuid: string;
  context?: TryLinkIncidentContext;
}): Promise<TryLinkIncidentResult> {
  try {
    await linkIncidentToDisaster(disasterUuid, incidentUuid);
    return { ok: true };
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      return {
        ok: false,
        message:
          "This incident may already be linked to the selected disaster.",
      };
    }
    return {
      ok: false,
      message: getLinkFailureMessage(context),
    };
  }
}
