import { apiGet, apiPost } from "@/lib/api";
import type {
  CreateSavedLocationRequest,
  CreateSavedLocationResponse,
  SavedLocation,
  SavedLocationResponse,
  SavedLocationsResponse,
} from "@/types/locations";

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object";
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function nullableNumber(value: unknown): number | null {
  if (value == null) return null;
  const next = Number(value);
  return Number.isFinite(next) ? next : null;
}

function requiredNumber(value: unknown, fieldName: string): number {
  const next = Number(value);
  if (!Number.isFinite(next)) {
    throw new Error(`Saved location payload is missing ${fieldName}.`);
  }
  return next;
}

function requiredString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Saved location payload is missing ${fieldName}.`);
  }
  return value;
}

export function normalizeSavedLocation(value: unknown): SavedLocation {
  if (!isObject(value)) {
    throw new Error("Saved location payload is invalid.");
  }

  const location: SavedLocation = {
    id: requiredNumber(value.id, "id"),
    publicUuid: requiredString(value.publicUuid, "publicUuid"),
    latitude: requiredNumber(value.latitude, "latitude"),
    longitude: requiredNumber(value.longitude, "longitude"),
    addressText: nullableString(value.addressText),
    placeName: nullableString(value.placeName),
    adminAreaId: nullableNumber(value.adminAreaId),
    source: requiredString(value.source, "source"),
    createdByUserId: nullableNumber(value.createdByUserId),
    createdAt: requiredString(value.createdAt, "createdAt"),
  };

  if (typeof value.adminAreaResolved === "boolean") {
    location.adminAreaResolved = value.adminAreaResolved;
  }

  if ("adminAreaMatchedLevel" in value) {
    location.adminAreaMatchedLevel = nullableString(value.adminAreaMatchedLevel);
  }

  if ("distance_km" in value) {
    location.distance_km = nullableNumber(value.distance_km);
  }

  return location;
}

function normalizeLocationsResponse(value: unknown): SavedLocationsResponse {
  if (!isObject(value) || !Array.isArray(value.locations)) {
    throw new Error("Saved locations response did not include locations.");
  }

  return {
    locations: value.locations.map(normalizeSavedLocation),
  };
}

function normalizeLocationResponse(value: unknown): SavedLocationResponse {
  if (!isObject(value) || !("location" in value)) {
    throw new Error("Saved location response did not include location.");
  }

  return {
    location: normalizeSavedLocation(value.location),
  };
}

export async function getMySavedLocations(): Promise<SavedLocationsResponse> {
  return normalizeLocationsResponse(await apiGet<unknown>("/locations/my"));
}

export async function getSavedLocation(
  publicUuid: string,
): Promise<SavedLocationResponse> {
  return normalizeLocationResponse(
    await apiGet<unknown>(`/locations/${encodeURIComponent(publicUuid)}`),
  );
}

export async function createSavedLocation(
  body: CreateSavedLocationRequest,
): Promise<CreateSavedLocationResponse> {
  const data = await apiPost<unknown, CreateSavedLocationRequest>(
    "/locations",
    body,
  );

  if (!isObject(data) || !("location" in data)) {
    throw new Error("Create location response did not include location.");
  }

  return {
    message:
      typeof data.message === "string" ? data.message : "Location created",
    location: normalizeSavedLocation(data.location),
  };
}
