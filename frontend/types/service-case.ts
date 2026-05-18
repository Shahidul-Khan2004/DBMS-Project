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
}

export interface CitizenServiceCaseListResponse {
  service_cases: CitizenServiceCase[];
}

export interface ServiceCaseMessageResult {
  id: number;
  message_type: string;
  message_body: string;
  created_at: string;
}

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
  status_code: string;
  note?: string | null;
  changed_at: string;
  changed_by?: {
    public_uuid: string;
    full_name: string;
    actor_kind: string;
  } | null;
}

export interface ServiceCaseAssignment {
  id: number;
  assigned_to_user_public_uuid: string;
  assignment_status: string;
  created_at?: string;
  note?: string | null;
}

export interface ServiceCaseResolution {
  resolution_type: string;
  resolution_text: string;
  recommended_facility_id?: number | null;
  resolved_at?: string;
}

export interface ServiceCaseDetailResponse {
  service_case: OperationsServiceCase;
  status_history: ServiceCaseStatusHistoryItem[];
  messages: ServiceCaseMessageResult[];
  assignments: ServiceCaseAssignment[];
  resolution?: ServiceCaseResolution | null;
}
