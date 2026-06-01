import type {
  IntakeQueueItem,
  TriageQueueFilters,
} from "@/components/dispatcher/triage/types";

export function filterAndSortQueue(
  items: IntakeQueueItem[],
  filters: TriageQueueFilters,
): IntakeQueueItem[] {
  let result = [...items];

  if (filters.status !== "all") {
    result = result.filter((item) => item.status === filters.status);
  }

  if (filters.category !== "all") {
    result = result.filter((item) => item.category === filters.category);
  }

  result.sort((a, b) => {
    const diff = a.receivedMinutesAgo - b.receivedMinutesAgo;
    return filters.sort === "newest" ? diff : -diff;
  });

  return result;
}
