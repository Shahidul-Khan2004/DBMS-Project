import { sortNewestFirst } from "@/lib/sort";
import type { OperationsServiceCase } from "@/types/service-case";

const SERVICE_CASE_PRIORITY_RANK: Record<string, number> = {
  urgent: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function getServiceCasePriorityRank(priorityLevel: string | null | undefined) {
  if (!priorityLevel) return 99;
  return SERVICE_CASE_PRIORITY_RANK[priorityLevel] ?? 99;
}

function getTimestampValues(serviceCase: OperationsServiceCase) {
  return [serviceCase.last_updated, serviceCase.created_at];
}

/** Urgent → high → medium → low, then most recently updated within each rank. */
export function sortServiceCasesByPriorityThenUpdated(
  cases: OperationsServiceCase[],
): OperationsServiceCase[] {
  const ranks = [0, 1, 2, 3, 99];
  const result: OperationsServiceCase[] = [];

  for (const rank of ranks) {
    const group = cases.filter(
      (serviceCase) =>
        getServiceCasePriorityRank(serviceCase.priority_level) === rank,
    );
    result.push(...sortNewestFirst(group, getTimestampValues));
  }

  return result;
}
