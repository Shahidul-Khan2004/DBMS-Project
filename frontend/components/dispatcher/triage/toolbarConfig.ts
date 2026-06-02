import type {
  TriageCategoryFilter,
  TriageSortOrder,
  TriageStatusFilter,
} from "@/components/dispatcher/triage/types";

export const TRIAGE_STATUS_FILTER_OPTIONS: ReadonlyArray<{
  value: TriageStatusFilter;
  label: string;
}> = [
  { value: "all", label: "All Pending" },
  { value: "received", label: "Awaiting Decision" },
  { value: "under_review", label: "Verification Required" },
];

export const TRIAGE_CATEGORY_FILTER_OPTIONS: ReadonlyArray<{
  value: TriageCategoryFilter;
  label: string;
}> = [
  { value: "all", label: "All Categories" },
  { value: "fire", label: "Fire" },
  { value: "medical", label: "Medical" },
  { value: "infrastructure_emergency", label: "Infrastructure Emergency" },
  { value: "crime_public_safety", label: "Crime / Public Safety" },
];

export const TRIAGE_SORT_OPTIONS: ReadonlyArray<{
  value: TriageSortOrder;
  label: string;
}> = [
  { value: "newest", label: "Newest First" },
  { value: "oldest", label: "Oldest First" },
];
