export const INCIDENT_CATEGORY_OPTIONS = [
  { value: "medical", label: "Medical" },
  { value: "crime_public_safety", label: "Crime / Public Safety" },
  { value: "fire", label: "Fire" },
  { value: "natural_disaster", label: "Natural Disaster" },
  { value: "infrastructure_emergency", label: "Infrastructure Emergency" },
  { value: "relief_request", label: "Relief Request" },
  { value: "blood_request", label: "Blood Request" },
] as const;

export type IncidentCategoryCode =
  (typeof INCIDENT_CATEGORY_OPTIONS)[number]["value"];
