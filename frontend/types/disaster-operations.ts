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

export type DisasterStatusHistoryEntry = {
  status_code?: string;
  note?: string | null;
  recorded_at?: string;
  actor_user_public_uuid?: string | null;
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
  location_admin_area_id?: number | null;
};

export type DisasterIncidentCandidate = {
  incident_public_uuid: string;
  incident_code?: string;
  title?: string;
  incident_status?: string;
  reported_at?: string;
  location_upazila_name?: string | null;
  in_affected_upazila?: number | boolean;
};

export type DisasterShelterActivation = {
  shelter_activation_public_uuid?: string;
  shelter_activation_id?: number;
  facility_public_uuid?: string;
  facility_name?: string;
  activation_status?: string;
  activation_source?: string;
  effective_capacity?: number | null;
  latest_occupancy?: number | null;
  available_capacity?: number | null;
  is_over_capacity?: boolean | null;
  managing_agency_name?: string | null;
  managing_agency_public_uuid?: string | null;
};

export type DisasterReliefHubActivation = {
  relief_hub_public_uuid?: string;
  relief_hub_activation_id?: number;
  facility_public_uuid?: string;
  facility_name?: string;
  activation_status?: string;
  activation_source?: string;
};

export type DisasterReliefInventoryRow = {
  relief_hub_activation_id?: number;
  facility_name?: string;
  item_code?: string;
  quantity_on_hand?: number;
};

export type DisasterReliefRequestShortage = {
  relief_request_id?: number;
  relief_item_code?: string;
  quantity_requested?: number;
  quantity_delivered?: number;
  quantity_short?: number;
};

export type DisasterReliefRequest = {
  relief_request_id?: number;
  relief_request_public_uuid: string;
  request_code?: string;
  status_code: string;
  shelter_activation_public_uuid?: string;
  shelter_facility_name?: string;
  shortages?: DisasterReliefRequestShortage[];
};

export type DisasterAuditLog = {
  id?: number;
  action?: string;
  entity_type?: string;
  entity_id?: number;
  details_json?: unknown;
  created_at?: string;
  actor_user_public_uuid?: string | null;
};

export type DisasterDashboardResponse = {
  disaster: DisasterDetail;
  status_history?: DisasterStatusHistoryEntry[];
  declarations: DisasterDeclaration[];
  affected_areas: DisasterAffectedArea[];
  responsibilities?: DisasterResponsibility[];
  linked_incidents?: DisasterLinkedIncident[];
  linked_incident_status_counts?: unknown[];
  shelters?: DisasterShelterActivation[];
  relief_hubs?: DisasterReliefHubActivation[];
  inventory_by_hub?: DisasterReliefInventoryRow[];
  relief_requests?: DisasterReliefRequest[];
  recent_audit_logs?: DisasterAuditLog[];
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
  impactLevel: "low" | "medium" | "high" | "severe";
  estimatedAffectedPeople?: number;
  shelterSupportRequired: boolean;
  reliefSupportRequired: boolean;
  assessmentNote?: string;
};

/** Optional fields for bulk add during declare wizard */
export type DisasterAssessmentInput = {
  impactLevel?: DisasterAssessmentPayload["impactLevel"];
  estimatedAffectedPeople?: number;
  shelterSupportRequired?: boolean;
  reliefSupportRequired?: boolean;
  assessmentNote?: string;
};

export type AddAffectedAreasPayload = {
  upazilaAdminAreaIds?: number[];
  districtAdminAreaId?: number;
  assessment?: DisasterAssessmentInput;
};

export type InitialDeclarationPayload = {
  title: string;
  publicGuidance?: string;
  legalReference?: string;
  reason: string;
};

export type DeclarationAmendmentPayload = InitialDeclarationPayload;

export type DisasterStatusPayload = {
  statusCode: "resolved" | "closed" | "cancelled";
  note?: string;
};

export type AssignResponsibilityPayload = {
  agencyPublicUuid: string;
  responsibilityType:
    | "coordination"
    | "shelter_management"
    | "relief_management"
    | "medical_support"
    | "security_support"
    | "rescue_support";
  isLead?: boolean;
};

export type LinkIncidentPayload = {
  incidentPublicUuid: string;
  linkNote?: string;
};

export type UnlinkIncidentPayload = {
  reason: string;
};

export type ActivateShelterPayload = {
  facilityPublicUuid: string;
  usableCapacityOverride?: number;
  manualOverrideNote?: string;
};

export type ActivateReliefHubPayload = {
  facilityPublicUuid: string;
  manualOverrideNote?: string;
};

export type ShelterManagingAgencyPayload = {
  agencyPublicUuid: string;
};

export type ShelterOccupancyPayload = {
  peopleCount: number;
};

export type StockReceiptPayload = {
  reliefItemCode: string;
  quantityReceived: number;
  note?: string;
};

export type ReliefRequestItemPayload = {
  reliefItemCode: string;
  quantityRequested: number;
};

export type CreateReliefRequestPayload = {
  shelterActivationPublicUuid: string;
  requestNote?: string;
  items: ReliefRequestItemPayload[];
};

export type ReliefRequestActionPayload = {
  note?: string;
};

export type ReliefDistributionItemPayload = {
  reliefItemCode: string;
  quantityDelivered: number;
};

export type CreateReliefDistributionPayload = {
  reliefRequestPublicUuid: string;
  sourceHubActivationPublicUuid: string;
  items: ReliefDistributionItemPayload[];
  note?: string;
};

export type DisasterIncidentCandidatesResponse = {
  incidents: DisasterIncidentCandidate[];
};

export type DisasterLinkedIncidentsResponse = {
  incidents: DisasterLinkedIncident[];
};

export type PostDisasterStatusResponse = {
  disaster: Pick<DisasterDetail, "public_uuid" | "status_code" | "ended_at">;
};
