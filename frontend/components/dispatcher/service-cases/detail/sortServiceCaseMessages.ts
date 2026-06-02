import type { ServiceCaseMessageResult } from "@/types/service-case";

function timestampMs(value: string | null | undefined) {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : 0;
}

export function sortServiceCaseMessagesNewestFirst(
  messages: ServiceCaseMessageResult[],
): ServiceCaseMessageResult[] {
  return [...messages].sort((left, right) => {
    const diff =
      timestampMs(right.created_at) - timestampMs(left.created_at);
    if (diff !== 0) return diff;
    return String(right.id).localeCompare(String(left.id));
  });
}
