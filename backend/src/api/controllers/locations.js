import * as locationService from "../../services/locationService.js";
import * as savedLocationService from "../../services/savedLocationService.js";
import { reverseGeocodeBarikoi, searchPlacesBarikoi } from "../../integrations/barikoiReverseGeocoder.js";
import BackendError from "../../lib/BackendError.js";
import pool from "../../config/db.js";
import { resolveAdminAreaFromCoordinates } from "../../services/adminAreaFromGpsService.js";
import { getAdministrativeAreaLabelById } from "../../repositories/administrativeAreaRepo.js";

export async function postLocation(req, res) {
  const body = req.validated?.body ?? req.body;
  const location = await locationService.createLocationForActor(req.actorUserId, body);
  res.status(201).json({
    message: "Location created",
    location,
  });
}

export async function getMyLocations(req, res) {
  const query = req.validated?.query ?? req.query;
  const locations = await savedLocationService.listSavedLocationsForActor(req.actorUserId, query);
  res.status(200).json({ locations });
}

export async function getLocationSearch(req, res) {
  const query = String(req.query.query ?? "").trim();
  if (!query) {
    throw new BackendError(400, "INVALID_LOCATION_SEARCH_QUERY", "Query parameter is required");
  }

  if (!String(process.env.BARIKOI_API_KEY ?? "").trim()) {
    throw new BackendError(
      503,
      "BARIKOI_API_KEY_MISSING",
      "Location search is unavailable because the Barikoi API key is not configured.",
    );
  }

  const { places, httpStatus, authOrQuotaFailure } = await searchPlacesBarikoi({
    query,
    limit: 8,
  });

  if (authOrQuotaFailure) {
    if (authOrQuotaFailure.kind === "invalid_key") {
      throw new BackendError(
        503,
        "BARIKOI_API_KEY_REJECTED",
        "Location search failed because the Barikoi API key was rejected.",
      );
    }

    throw new BackendError(
      503,
      "BARIKOI_QUOTA_EXCEEDED",
      "Location search failed because the Barikoi API usage limit was reached.",
    );
  }

  if (httpStatus == null || httpStatus < 200 || httpStatus >= 300) {
    throw new BackendError(
      503,
      "BARIKOI_SEARCH_UNAVAILABLE",
      "Location search is temporarily unavailable.",
    );
  }

  res.status(200).json({ places });
}

export async function getLocationReverse(req, res) {
  const latitude = Number(req.query.latitude);
  const longitude = Number(req.query.longitude);

  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
    throw new BackendError(
      400,
      "INVALID_LOCATION_REVERSE_COORDINATES",
      "Latitude and longitude query parameters are required.",
    );
  }

  const reverseResult = await reverseGeocodeBarikoi({
    latitude,
    longitude,
  });
  const { place, authOrQuotaFailure } = reverseResult;

  if (authOrQuotaFailure) {
    if (authOrQuotaFailure.kind === "invalid_key") {
      throw new BackendError(
        503,
        "BARIKOI_API_KEY_REJECTED",
        "Reverse location lookup failed because the Barikoi API key was rejected.",
      );
    }

    throw new BackendError(
      503,
      "BARIKOI_QUOTA_EXCEEDED",
      "Reverse location lookup failed because the Barikoi API usage limit was reached.",
    );
  }

  const placeName = [place.area, place.city, place.thana].filter(Boolean).join(", ");
  const addressText =
    place.address?.trim() ||
    [place.area, place.thana, place.city].filter(Boolean).join(", ") ||
    undefined;
  const barikoiAdminAreaLabel =
    [place.upazila, place.district, place.division].filter(Boolean).join(", ") || undefined;

  let adminAreaId;
  let adminAreaLabel = barikoiAdminAreaLabel;

  try {
    const resolved = await resolveAdminAreaFromCoordinates(pool, latitude, longitude, {
      prefetchedBarikoiResult: reverseResult,
    });
    if (resolved?.adminAreaId != null) {
      adminAreaId = resolved.adminAreaId;
      const dbLabel = await getAdministrativeAreaLabelById(pool, resolved.adminAreaId);
      if (dbLabel) {
        adminAreaLabel = dbLabel;
      }
    }
  } catch {
    // Admin area matching is optional for reverse lookup display.
  }

  res.status(200).json({
    addressText,
    placeName: placeName || undefined,
    adminAreaId,
    adminAreaLabel,
  });
}

export async function getLocationByPublicUuid(req, res) {
  const params = req.validated?.params ?? req.params;
  const location = await locationService.getLocationForActor(
    params.publicUuid,
    req.actorUserId,
    req.authz?.permissions ?? [],
  );
  if (!location) {
    throw new BackendError(404, "LOCATION_NOT_FOUND", "Location not found");
  }
  res.status(200).json({ location });
}

export async function saveLocation(req, res) {
  const params = req.validated?.params ?? req.params;
  const label = req.validated?.body?.label ?? null;
  const result = await savedLocationService.saveLocationForActor(req.actorUserId, params.publicUuid, { label });
  res.status(200).json({
    message: "Location saved",
    savedLocationPublicUuid: result.savedLocationPublicUuid,
    label: result.label,
  });
}

export async function unsaveLocation(req, res) {
  const params = req.validated?.params ?? req.params;
  await savedLocationService.unsaveLocationForActor(req.actorUserId, params.publicUuid);
  res.status(200).json({ message: "Location removed from saved" });
}