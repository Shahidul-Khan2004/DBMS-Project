import type {
  DisasterAffectedArea,
  DisasterDeclaration,
  DisasterDetail,
  DisasterLinkedIncident,
  DisasterListItem,
  DisasterReliefHubActivation,
  DisasterReliefInventoryRow,
  DisasterReliefRequest,
  DisasterShelterActivation,
} from "@/types/disaster-operations";

export type AgencyDisasterListResponse = {
  limit: number;
  offset: number;
  disasters: DisasterListItem[];
};

export type AgencyDisasterDetailResponse = {
  disaster: DisasterDetail;
  declarations: DisasterDeclaration[];
  affected_areas: DisasterAffectedArea[];
  shelters: DisasterShelterActivation[];
  relief_hubs: DisasterReliefHubActivation[];
  inventory_by_hub: DisasterReliefInventoryRow[];
  relief_requests: DisasterReliefRequest[];
};

export type AgencyDisasterSheltersResponse = {
  disaster_public_uuid: string;
  shelters: DisasterShelterActivation[];
};

export type AgencyDisasterReliefHubsResponse = {
  disaster_public_uuid: string;
  relief_hubs: DisasterReliefHubActivation[];
};

export type AgencyReliefHubStockReceiptPayload = {
  reliefItemCode: string;
  quantityReceived: number;
  note?: string;
};

export type AgencyReliefHubStockReceiptResponse = {
  receipt: {
    public_uuid: string;
    quantity_received: number;
  };
};

export type AgencyDisasterReliefRequestsResponse = {
  disaster_public_uuid: string;
  relief_requests: DisasterReliefRequest[];
};

export type AgencyDisasterLinkedIncident = DisasterLinkedIncident & {
  participation_status?: string | null;
};

export type AgencyDisasterIncidentsResponse = {
  disaster_public_uuid: string;
  incidents: AgencyDisasterLinkedIncident[];
};

export type AgencyShelterOccupancyPayload = {
  peopleCount: number;
};

export type AgencyReliefRequestItemPayload = {
  reliefItemCode: string;
  quantityRequested: number;
};

export type AgencyCreateReliefRequestPayload = {
  shelterActivationPublicUuid: string;
  requestNote?: string;
  items: AgencyReliefRequestItemPayload[];
};

export type AgencyCreateReliefRequestResponse = {
  request: {
    public_uuid: string;
    request_code: string;
    status_code: string;
  };
};

export type AgencyShelterOccupancyResponse = {
  snapshot: DisasterShelterActivation;
};
