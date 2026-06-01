export type DisasterListItem = {
  public_uuid: string;
  event_code: string;
  title: string;
  status_code: string;
  severity_level?: string | null;
  event_type_code: string;
  event_type_name?: string | null;
};

export type DisasterListResponse = {
  disasters: DisasterListItem[];
};

export type DisasterDetail = {
  public_uuid: string;
  event_code: string;
  title: string;
  description?: string | null;
  public_guidance?: string | null;
  severity_level?: string | null;
  status_code: string;
  event_type_code: string;
  event_type_name?: string | null;
  started_at?: string | null;
  ended_at?: string | null;
  created_at?: string;
  updated_at?: string;
};

export type DisasterDeclaration = {
  public_uuid: string;
  declaration_code?: string;
  declaration_kind?: string;
  title: string;
  public_guidance?: string | null;
  legal_reference?: string | null;
  reason?: string | null;
  issued_at?: string;
  issued_by_user_public_uuid?: string | null;
};

export type DisasterAffectedArea = {
  affected_area_public_uuid: string;
  admin_area_id?: number;
  upazila_name?: string;
  district_name?: string;
  division_name?: string;
  impact_level?: string | null;
  estimated_affected_people?: number | null;
  shelter_support_required?: boolean | null;
  relief_support_required?: boolean | null;
  assessment_note?: string | null;
  assessment_recorded_at?: string | null;
};

export type DisasterResponsibility = {
  id?: number;
  agency_public_uuid: string;
  agency_name?: string;
  responsibility_type: string;
  is_lead?: boolean;
  assigned_at?: string;
};

export type DisasterLinkedIncident = {
  incident_public_uuid: string;
  incident_code?: string;
  title?: string;
  incident_status?: string;
  linked_at?: string;
  link_note?: string | null;
  location_upazila_name?: string | null;
};

export type DisasterShelterActivation = {
  public_uuid?: string;
  facility_public_uuid?: string;
  facility_name?: string;
  activation_status?: string;
  usable_capacity?: number | null;
};

export type DisasterReliefHub = {
  public_uuid?: string;
  facility_public_uuid?: string;
  facility_name?: string;
  activation_status?: string;
};

export type DisasterDashboardResponse = {
  disaster: DisasterDetail;
  status_history?: unknown[];
  declarations: DisasterDeclaration[];
  affected_areas: DisasterAffectedArea[];
  responsibilities?: DisasterResponsibility[];
  linked_incidents?: DisasterLinkedIncident[];
  shelters?: DisasterShelterActivation[];
  relief_hubs?: DisasterReliefHub[];
  relief_requests?: unknown[];
  recent_audit_logs?: unknown[];
};

export type CreateDisasterPayload = {
  eventTypeCode: string;
  title: string;
  description?: string;
  severityLevel?: string;
  startedAt?: string;
};

export type CreateDisasterResponse = {
  disaster: DisasterDetail;
};

export type DisasterAssessmentPayload = {
  impactLevel?: "low" | "medium" | "high" | "severe";
  estimatedAffectedPeople?: number;
  shelterSupportRequired?: boolean;
  reliefSupportRequired?: boolean;
  assessmentNote?: string;
};

export type AddAffectedAreasPayload = {
  upazilaAdminAreaIds?: number[];
  districtAdminAreaId?: number;
  assessment?: DisasterAssessmentPayload;
};

export type InitialDeclarationPayload = {
  title: string;
  publicGuidance?: string;
  legalReference?: string;
  reason: string;
};
