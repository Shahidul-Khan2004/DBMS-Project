import type { IntakeLocationSource } from "@/types/intake";

export interface SavedLocation {
  id: number;
  publicUuid: string;
  latitude: number;
  longitude: number;
  addressText: string | null;
  placeName: string | null;
  adminAreaId: number | null;
  source: IntakeLocationSource | string;
  createdByUserId: number | null;
  createdAt: string;
  adminAreaResolved?: boolean;
  adminAreaMatchedLevel?: string | null;
  distance_km?: number | null;
}

export interface CreateSavedLocationRequest {
  latitude: number;
  longitude: number;
  address_text?: string;
  place_name?: string;
  admin_area_id?: number;
  source: IntakeLocationSource;
}

export interface SavedLocationsResponse {
  locations: SavedLocation[];
}

export interface SavedLocationResponse {
  location: SavedLocation;
}

export interface CreateSavedLocationResponse {
  message: string;
  location: SavedLocation;
}

export interface SaveLocationResponse {
  message: string;
  savedLocationPublicUuid: string;
  label: string | null;
}
