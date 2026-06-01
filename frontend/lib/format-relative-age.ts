export function formatRelativeAge(iso: string | null | undefined): string {
  if (!iso) return "unknown time";
  const ms = new Date(iso).getTime();
  if (!Number.isFinite(ms)) return "unknown time";

  const diffMin = Math.max(0, Math.floor((Date.now() - ms) / 60000));
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin} min ago`;

  const hours = Math.floor(diffMin / 60);
  if (hours < 48) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function timestampMs(value: string | null | undefined): number {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : 0;
}

export function formatIntakeAgeLabel(
  status: string,
  reportedAt: string | null | undefined,
  updatedAt: string | null | undefined,
): string {
  const reportedMs = timestampMs(reportedAt);
  const updatedMs = timestampMs(updatedAt);

  if (
    status === "under_review" &&
    updatedMs > 0 &&
    (reportedMs === 0 || updatedMs !== reportedMs)
  ) {
    return `Updated ${formatRelativeAge(updatedAt)}`;
  }

  return `Received ${formatRelativeAge(reportedAt)}`;
}
