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
  createdByUserId: number;
  createdAt: string;
  adminAreaResolved?: boolean;
  adminAreaMatchedLevel?: string | null;
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
