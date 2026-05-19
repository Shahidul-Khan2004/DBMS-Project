import { apiGet } from "@/lib/api";
import type { CitizenIncidentListResponse } from "@/types/citizen-incident";

export function getMyIncidents() {
  return apiGet<CitizenIncidentListResponse>("/intake/reports/my/incidents");
}
