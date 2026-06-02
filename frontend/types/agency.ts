import type { IntakeStructuredLocation } from "@/types/intake";

export type AgencyDispatchStatusCode =
  | "assigned"
  | "dispatched"
  | "arrived"
  | "completed"
  | "cancelled";

export type AgencyDispatchStatusAction =
  | "dispatched"
  | "arrived"
  | "completed"
  | "cancelled";

export type AgencyUnitStatusCode = "available" | "busy";

export type AgencyResponseLogType =
  | "update"
  | "hazard"
  | "casualty"
  | "resource_need"
  | "completion_note";

export type AgencyMeAgency = {
  public_uuid: string;
  agency_code: string;
  name: string;
  description: string | null;
  agency_type_code: string;
  is_active: boolean;
};

export type AgencyMeMembership = {
  public_uuid: string;
  membership_role: string;
  membership_status: string;
  joined_at: string;
};

export type AgencyMeCounts = {
  total_units: number;
  active_units: number;
  open_dispatches: number;
  active_incidents: number;
};

export type AgencyMeResponse = {
  agency: AgencyMeAgency;
  membership: AgencyMeMembership;
  counts: AgencyMeCounts;
};

export type AgencyIncident = {
  incident_public_uuid: string;
  incident_code: string;
  status_code: string;
  participation_status: string;
};

export type AgencyIncidentsListResponse = {
  limit: number;
  offset: number;
  incidents: AgencyIncident[];
};

export type AgencyDispatchIncidentSummary = {
  public_uuid: string;
  incident_code: string;
  title: string;
};

export type AgencyDispatchUnitSummary = {
  public_uuid: string;
  unit_code: string;
  unit_name: string;
};

export type AgencyDispatch = {
  public_uuid: string;
  status_code: AgencyDispatchStatusCode;
  priority_level: string;
  assigned_at: string | null;
  dispatched_at: string | null;
  arrived_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  incident: AgencyDispatchIncidentSummary;
  unit: AgencyDispatchUnitSummary;
};

export type AgencyDispatchesListResponse = {
  limit: number;
  offset: number;
  dispatches: AgencyDispatch[];
};

export type AgencyUnit = {
  public_uuid: string;
  unit_code: string;
  unit_name: string;
  unit_type_code: string;
  status_code: string;
  is_active: boolean;
};

export type AgencyUnitsListResponse = {
  limit: number;
  offset: number;
  units: AgencyUnit[];
};

export type AgencyResponseLog = {
  id: number;
  log_type: string;
  message: string;
  logged_at: string;
  dispatch_public_uuid: string | null;
};

export type AgencyResponseLogsListResponse = {
  incident_public_uuid: string;
  limit: number;
  offset: number;
  response_logs: AgencyResponseLog[];
};

export type AgencyCreateResponseLogResponse = {
  response_log: AgencyResponseLog;
};

export type AgencyNote = {
  id: number;
  event_type: string;
  event_title: string;
  event_description: string | null;
  event_time: string;
  created_at: string;
};

export type AgencyNotesListResponse = {
  incident_public_uuid: string;
  limit: number;
  offset: number;
  notes: AgencyNote[];
};

export type AgencyListQuery = {
  limit?: number;
  offset?: number;
};

export type AgencyPatchDispatchStatusBody = {
  statusCode: AgencyDispatchStatusAction;
  note?: string;
};

export type AgencyPatchDispatchStatusResponse = {
  dispatch: {
    public_uuid: string;
    status_code: AgencyDispatchStatusCode;
    dispatched_at?: string | null;
    arrived_at?: string | null;
    completed_at?: string | null;
    cancelled_at?: string | null;
  };
};

export type AgencyCreateUnitBody = {
  unit_code: string;
  unit_name: string;
  unit_type_code: string;
  base_location: IntakeStructuredLocation;
};

export type AgencyPatchUnitBody = {
  unit_code?: string;
  unit_name?: string;
  base_location?: IntakeStructuredLocation;
};

export type AgencyPatchUnitStatusBody = {
  status_code: AgencyUnitStatusCode;
  note?: string;
};

export type AgencyCreateUnitResponse = {
  unit: AgencyUnit;
};

export type AgencyPatchUnitResponse = {
  unit: AgencyUnit;
};

export type AgencyDeactivateUnitResponse = {
  message: string;
  unit: Pick<AgencyUnit, "public_uuid" | "is_active"> & Partial<AgencyUnit>;
};

export type AgencyCreateResponseLogBody = {
  log_type?: AgencyResponseLogType;
  message: string;
  dispatch_public_uuid?: string;
};
