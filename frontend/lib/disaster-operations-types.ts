import type {
  DisasterAuditLog,
  DisasterAffectedArea,
  DisasterDashboardResponse,
  DisasterDeclaration,
  DisasterDetail,
  DisasterLinkedIncident as BaseDisasterLinkedIncident,
  DisasterListItem,
  DisasterReliefHubActivation,
  DisasterReliefRequest,
  DisasterResponsibility,
  DisasterShelterActivation,
  DisasterStatusHistoryEntry,
} from "@/types/disaster-operations";

export type OperationsDisasterSummary = DisasterListItem;

export type DisasterLinkedIncident = BaseDisasterLinkedIncident & {
  distance_km?: number | null;
};

export type OperationsDisasterDashboard = Omit<
  DisasterDashboardResponse,
  "linked_incidents"
> & {
  disaster: DisasterDetail;
  status_history?: DisasterStatusHistoryEntry[];
  declarations: DisasterDeclaration[];
  affected_areas: DisasterAffectedArea[];
  responsibilities?: DisasterResponsibility[];
  linked_incidents?: DisasterLinkedIncident[];
  shelters?: DisasterShelterActivation[];
  relief_hubs?: DisasterReliefHubActivation[];
  relief_requests?: DisasterReliefRequest[];
  recent_audit_logs?: DisasterAuditLog[];
};
