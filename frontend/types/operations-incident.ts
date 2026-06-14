export type OperationsIncidentLocation = {
  public_uuid: string;
  latitude: number;
  longitude: number;
  address_text: string | null;
  place_name: string | null;
  admin_area_id: number | null;
  source: string | null;
};

export type OperationsIncidentDetail = {
  id?: number;
  public_uuid: string;
  incident_code: string;
  title: string;
  description: string | null;
  origin_type: string;
  status_code: string;
  category_code: string;
  severity_code: string;
  outcome_code: string | null;
  reported_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
  location?: OperationsIncidentLocation | null;
};

export type OperationsLinkedIntakeReport = {
  link_type: string;
  linked_at: string;
  link_note?: string | null;
  intake_public_uuid: string;
  intake_report_code: string;
  intake_summary: string;
  intake_status: string;
  location?: OperationsIncidentLocation | null;
};

export type OperationsTimelineEvent = {
  id: string;
  event_type: string;
  event_title: string;
  event_description: string | null;
  event_time: string;
  created_at: string;
};

export type OperationsParticipatingAgency = {
  agency_public_uuid: string;
  agency_name: string;
  agency_type_code: string;
  is_lead_agency: boolean;
  participation_status: string;
  joined_at: string;
};

export type OperationsIncidentDispatchUnit = {
  public_uuid: string;
  unit_code: string;
  unit_name: string;
  unit_type_code: string;
  status_code: string;
};

export type OperationsIncidentDispatchAgency = {
  public_uuid: string;
  agency_name: string;
  agency_type_code: string;
};

export type OperationsIncidentDispatch = {
  public_uuid: string;
  unit_public_uuid: string;
  status_code: string;
  priority_level: string;
  assigned_at: string | null;
  dispatched_at: string | null;
  arrived_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  unit: OperationsIncidentDispatchUnit;
  owning_agency: OperationsIncidentDispatchAgency;
};

export type OperationsIncidentDetailResponse = {
  incident: OperationsIncidentDetail;
  linked_intake_reports?: OperationsLinkedIntakeReport[];
  timeline_preview?: OperationsTimelineEvent[];
  participating_agencies?: OperationsParticipatingAgency[];
  dispatches?: OperationsIncidentDispatch[];
};

export type OperationsAgencyWorkloadItem = {
  agency_public_uuid: string;
  agency_name: string;
  active_incidents: number;
  total_units: number;
  available_units: number;
  busy_units: number;
  total_dispatches: number;
};

export type OperationsAgenciesWorkloadResponse = {
  agencies: OperationsAgencyWorkloadItem[];
};

export type AssignIncidentAgencyPayload = {
  agencyPublicUuid: string;
  isLeadAgency: boolean;
};

export type AssignIncidentAgencyResponse = {
  message?: string;
  participation: OperationsParticipatingAgency;
};

export type AvailableIncidentUnit = {
  public_uuid: string;
  unit_code: string;
  unit_name: string;
  status_code: string;
  agency_public_uuid: string;
  agency_name: string;
  unit_type_code: string;
  distance_km?: number | null;
};

export type AvailableIncidentUnitsResponse = {
  incident_public_uuid: string;
  units: AvailableIncidentUnit[];
};

export type DispatchPriorityLevel = "low" | "medium" | "high" | "critical";

export type CreateIncidentDispatchPayload = {
  unitPublicUuid: string;
  priorityLevel: DispatchPriorityLevel;
  note?: string;
};

export type OperationsDispatchRecord = {
  public_uuid: string;
  incident_public_uuid: string;
  unit_public_uuid: string;
  status_code: string;
  priority_level: string;
  assigned_at: string | null;
  dispatched_at: string | null;
  arrived_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
};

export type CreateIncidentDispatchResponse = {
  message?: string;
  dispatch: OperationsDispatchRecord;
};

export type UpdateDispatchStatusCode =
  | "dispatched"
  | "arrived"
  | "completed"
  | "cancelled";

export type UpdateDispatchStatusPayload = {
  statusCode: UpdateDispatchStatusCode;
  note?: string;
};

export type UpdateDispatchStatusResponse = {
  message?: string;
  dispatch: OperationsDispatchRecord;
};

export type PatchIncidentStatusPayload = {
  statusCode: "resolved" | "closed" | "cancelled";
  outcomeCode:
    | "resolved"
    | "false_alarm"
    | "duplicate_incident"
    | "cancelled"
    | "transferred"
    | "unresolved";
  note: string;
};

export type PatchIncidentStatusResponse = {
  message?: string;
  incident: OperationsIncidentDetail;
};

export type AddIncidentOperationalNotePayload = {
  title: string;
  description?: string;
};

export type AddIncidentOperationalNoteResponse = {
  message: string;
  note: OperationsTimelineEvent;
};

export type UnlinkIncidentIntakeReportPayload = {
  reason: string;
};

export type UnlinkIncidentIntakeReportResponse = {
  message: string;
  unlink: {
    incident_public_uuid: string;
    incident_code: string;
    intake_report_public_uuid: string;
    intake_report_code: string;
    link_type: string;
    unlinked_at: string;
    unlink_reason: string;
    intake_status: string;
  };
};

export type OperationsResponseTiming = {
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
};

export type OperationsResponseTimingResponse = {
  timing: OperationsResponseTiming;
};

export type CreateStandaloneIncidentLocationPayload = {
  latitude: number;
  longitude: number;
  address_text?: string;
  place_name?: string | null;
  admin_area_id?: number;
  source: "dispatcher_selected";
};

export type CreateStandaloneIncidentPayload = {
  categoryCode: string;
  severityCode: "low" | "medium" | "high" | "critical";
  title: string;
  description?: string;
  reportedAt?: string;
  location: CreateStandaloneIncidentLocationPayload;
};

export type CreateStandaloneIncidentResponse = {
  message: string;
  incident: { public_uuid: string };
};
