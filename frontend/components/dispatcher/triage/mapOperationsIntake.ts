import { formatBadgeLabel } from "@/components/ui/Badge";
import { formatIntakeAgeLabel } from "@/lib/format-relative-age";
import type { OperationsIntakeReport } from "@/types/operations-intake";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";

const NO_DESCRIPTION = "No additional description provided.";
const LOCATION_UNAVAILABLE = "Reported location unavailable";

const PENDING_STATUSES = new Set(["received", "under_review"]);

function minutesAgo(iso: string | null | undefined): number {
  if (!iso) return Number.MAX_SAFE_INTEGER;
  const ms = new Date(iso).getTime();
  if (!Number.isFinite(ms)) return Number.MAX_SAFE_INTEGER;
  return Math.max(0, Math.floor((Date.now() - ms) / 60000));
}

function formatLocationText(row: OperationsIntakeReport): string {
  const loc = row.location;
  if (!loc) return LOCATION_UNAVAILABLE;
  return (
    loc.address_text?.trim() ||
    loc.place_name?.trim() ||
    LOCATION_UNAVAILABLE
  );
}

export function mapOperationsIntakeToQueueItem(
  row: OperationsIntakeReport,
): IntakeQueueItem | null {
  if (!PENDING_STATUSES.has(row.intake_status)) {
    return null;
  }

  const status = row.intake_status as "received" | "under_review";
  const loc = row.location;
  const placeName = loc?.place_name?.trim() ?? "";
  const hasValidCoordinates =
    loc != null &&
    Number.isFinite(loc.latitude) &&
    Number.isFinite(loc.longitude);

  return {
    id: row.public_uuid,
    reportCode: row.report_code?.trim() || row.public_uuid,
    status,
    summary: row.summary?.trim() || "Untitled report",
    category: row.category_code
      ? formatBadgeLabel(row.category_code)
      : "Uncategorized",
    description: row.description?.trim() || NO_DESCRIPTION,
    channel: row.channel_code
      ? formatBadgeLabel(row.channel_code)
      : "Unknown channel",
    ageLabel: formatIntakeAgeLabel(
      row.intake_status,
      row.reported_at,
      row.updated_at,
    ),
    location: {
      addressText: formatLocationText(row),
      areaName: placeName,
      districtName: "",
      ...(hasValidCoordinates
        ? { latitude: loc.latitude, longitude: loc.longitude }
        : {}),
    },
    receivedMinutesAgo: minutesAgo(row.reported_at),
  };
}

export function mapOperationsIntakeList(
  rows: OperationsIntakeReport[],
): IntakeQueueItem[] {
  const items: IntakeQueueItem[] = [];
  for (const row of rows) {
    const mapped = mapOperationsIntakeToQueueItem(row);
    if (mapped) items.push(mapped);
  }
  return items;
}
