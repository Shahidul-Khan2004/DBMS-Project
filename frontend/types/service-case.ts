export interface ServiceCaseLocation {
  public_uuid: string;
  latitude: number;
  longitude: number;
  address_text: string | null;
  place_name: string | null;
  admin_area_id: number | null;
  source: string;
}

export interface CitizenServiceCase {
  public_uuid: string;
  case_code: string;
  title: string;
  description: string | null;
  priority_level: string | null;
  status_code: string | null;
  category_code: string | null;
  intake_public_uuid: string | null;
  intake_report_code: string | null;
  last_updated: string;
  created_at: string;
  updated_at?: string;
  location?: ServiceCaseLocation | null;
  location_text?: string | null;
  linked_incident_public_uuid?: string | null;
  source_channel?: string | null;
}

export interface CitizenServiceCaseListResponse {
  service_cases: CitizenServiceCase[];
}

export type ServiceCaseMessageType =
  | "user_message"
  | "admin_reply"
  | "system_note"
  | string;

export interface ServiceCaseMessageResult {
  id: string;
  message_type: ServiceCaseMessageType;
  subject: string;
  body: string | null;
  message_body?: string | null;
  created_at: string | null;
  sender?: {
    public_uuid: string;
    full_name: string | null;
  } | null;
  is_internal?: boolean;
}

export interface ServiceCaseMessagesResponse {
  public_uuid: string;
  case_code: string;
  messages: ServiceCaseMessageResult[];
}

export type CitizenServiceCaseMessagesResponse = ServiceCaseMessagesResponse;

export interface ServiceCaseMessageResponse {
  message?: string;
  case_message?: ServiceCaseMessageResult;
}

export interface OperationsServiceCase extends CitizenServiceCase {
  assigned_to_user_public_uuid?: string | null;
}

export interface OperationsServiceCaseListResponse {
  service_cases: OperationsServiceCase[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

export interface ServiceCaseStatusHistoryItem {
  id?: string;
  status_code: string;
  note?: string | null;
  changed_at: string;
  changed_by?: {
    public_uuid: string;
    full_name: string | null;
    actor_kind?: string | null;
  } | null;
}

export interface ServiceCaseAssignmentUser {
  public_uuid: string;
  full_name: string | null;
}

export interface ServiceCaseAssignment {
  id: string | number;
  assignment_status: string;
  assigned_at?: string | null;
  ended_at?: string | null;
  note?: string | null;
  assigned_to: ServiceCaseAssignmentUser;
  assigned_by_public_uuid?: string | null;
  /** @deprecated list rows may still expose this */
  assigned_to_user_public_uuid?: string;
}

export type ServiceCaseResolutionType =
  | "advice_given"
  | "referred_to_facility"
  | "no_action_needed"
  | "duplicate";

export interface ServiceCaseResolution {
  id?: string;
  resolution_type: string;
  resolution_text: string;
  recommended_facility_id?: number | null;
  resolved_at?: string | null;
  resolved_by?: {
    public_uuid: string;
    full_name: string | null;
  } | null;
}

export interface ServiceCaseDetailResponse {
  service_case: OperationsServiceCase;
  status_history: ServiceCaseStatusHistoryItem[];
  messages: ServiceCaseMessageResult[];
  assignments: ServiceCaseAssignment[];
  resolution?: ServiceCaseResolution | null;
}

export interface PatchServiceCaseStatusPayload {
  statusCode: string;
  note?: string;
}

export interface PostServiceCaseMessagePayload {
  title: string;
  description?: string;
}

export interface PostServiceCaseResolvePayload {
  resolutionType: ServiceCaseResolutionType;
  resolutionText: string;
}

export interface IntakeEscalatePayload {
  severityCode: "low" | "medium" | "high" | "critical";
  escalationReason: string;
  incidentTitle?: string;
  incidentDescription?: string;
}

export interface IntakeEscalateResponse {
  message?: string;
  incident?: {
    public_uuid?: string;
    incident_code?: string;
    title?: string;
    origin_type?: string;
  };
  intake_public_uuid?: string;
}
