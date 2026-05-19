import type { IntakeLocation } from "@/types/intake";

export interface CitizenIncident {
  public_uuid: string;
  incident_code: string;
  title: string | null;
  description: string | null;
  origin_type: string | null;
  status_code: string;
  category_code: string;
  severity_code: string;
  intake_public_uuid: string;
  intake_report_code: string;
  reported_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  created_at: string;
  last_updated: string | null;
  location: IntakeLocation | null;
  location_text: string | null;
}

export interface CitizenIncidentListResponse {
  incidents: CitizenIncident[];
}
