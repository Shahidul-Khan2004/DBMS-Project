export type DispatchPriorityLevel = "low" | "medium" | "high" | "critical";

export type DispatchStatusCode =
  | "assigned"
  | "dispatched"
  | "arrived"
  | "completed"
  | "cancelled"
  | string;

export interface AgencyParticipation {
  agency_public_uuid: string;
  agency_name: string;
  is_lead_agency: boolean;
  participation_status: string;
  joined_at: string;
}

export interface AgencyParticipationResponse {
  message?: string;
  participation: AgencyParticipation;
}

export interface AvailableUnit {
  public_uuid: string;
  unit_code: string;
  unit_name: string;
  status_code: string;
  agency_public_uuid: string;
  agency_name: string;
  unit_type_code: string;
}

export interface AvailableUnitsResponse {
  incident_public_uuid: string;
  units: AvailableUnit[];
}

export interface Dispatch {
  public_uuid: string;
  incident_public_uuid: string;
  unit_public_uuid: string;
  status_code: DispatchStatusCode;
  priority_level: DispatchPriorityLevel | string;
  assigned_at: string | null;
  dispatched_at: string | null;
  arrived_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
}

export interface DispatchResponse {
  message?: string;
  dispatch: Dispatch;
}

export interface AgencyWorkload {
  agency_public_uuid: string;
  agency_name: string;
  active_incidents: number;
  total_units: number;
  available_units: number;
  busy_units: number;
  total_dispatches: number;
}

export interface AgencyWorkloadResponse {
  agencies: AgencyWorkload[];
}

export interface ResponseTiming {
  incident_public_uuid: string;
  incident_code: string;
  first_call_started_at: string | null;
  incident_created_at: string | null;
  first_agency_joined_at: string | null;
  first_unit_assigned_at: string | null;
  first_unit_dispatched_at: string | null;
  first_unit_arrived_at: string | null;
  call_to_incident_minutes: number | null;
  incident_to_agency_minutes: number | null;
  agency_to_dispatch_minutes: number | null;
  dispatch_to_arrival_minutes: number | null;
}

export interface ResponseTimingResponse {
  timing: ResponseTiming | null;
}
