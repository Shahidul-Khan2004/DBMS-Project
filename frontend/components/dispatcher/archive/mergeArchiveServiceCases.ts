import { sortNewestFirst } from "@/lib/sort";
import type { OperationsServiceCase } from "@/types/service-case";

function getServiceCaseTimestampValues(serviceCase: OperationsServiceCase) {
  return [serviceCase.last_updated, serviceCase.updated_at, serviceCase.created_at];
}

export function dedupeServiceCasesByPublicUuid(
  cases: OperationsServiceCase[],
): OperationsServiceCase[] {
  const seen = new Set<string>();
  const result: OperationsServiceCase[] = [];

  for (const serviceCase of cases) {
    const uuid = serviceCase.public_uuid?.trim();
    if (!uuid || seen.has(uuid)) continue;
    seen.add(uuid);
    result.push(serviceCase);
  }

  return result;
}

export function mergeArchiveServiceCases(
  ...groups: OperationsServiceCase[][]
): OperationsServiceCase[] {
  const merged = dedupeServiceCasesByPublicUuid(groups.flat());
  return sortNewestFirst(merged, getServiceCaseTimestampValues);
}
