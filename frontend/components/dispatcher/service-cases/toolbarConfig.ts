export const OPEN_STATUS_FILTER = "__open__";

/** Fixed API page size; not exposed in the dispatcher toolbar. */
export const SERVICE_CASE_LIST_FETCH_LIMIT = 50;

export const SERVICE_CASE_STATUS_FILTER_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: OPEN_STATUS_FILTER, label: "Open cases" },
  { value: "submitted", label: "Submitted" },
  { value: "under_review", label: "Under review" },
  { value: "awaiting_user_response", label: "Awaiting user response" },
] as const;

export const SERVICE_CASE_CATEGORY_FILTER_OPTIONS = [
  { value: "", label: "All categories" },
  { value: "medical", label: "Medical" },
  { value: "crime_public_safety", label: "Crime / Public Safety" },
  { value: "fire", label: "Fire" },
  { value: "natural_disaster", label: "Natural Disaster" },
  { value: "infrastructure_emergency", label: "Infrastructure" },
  { value: "relief_request", label: "Relief Request" },
  { value: "blood_request", label: "Blood Request" },
] as const;

export const SERVICE_CASE_PRIORITY_FILTER_OPTIONS = [
  { value: "", label: "All Priorities" },
  { value: "urgent", label: "Urgent" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
] as const;

export type ServiceCaseSortOrder =
  | "priority_first"
  | "recently_updated"
  | "oldest_updated";

export const SERVICE_CASE_SORT_OPTIONS: ReadonlyArray<{
  value: ServiceCaseSortOrder;
  label: string;
}> = [
  { value: "priority_first", label: "Priority First" },
  { value: "recently_updated", label: "Recently Updated" },
  { value: "oldest_updated", label: "Oldest Updated" },
];
