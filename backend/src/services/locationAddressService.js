import { reverseGeocodeBarikoi } from "../integrations/barikoiReverseGeocoder.js";

function toCoordFallback(latitude, longitude) {
  return `Coordinates: ${Number(latitude)}, ${Number(longitude)}`;
}

/**
 * Derive a final address/source pair for location writes.
 * - If caller provides non-blank address_text, preserve it and source.
 * - Else try reverse geocode (Barikoi).
 * - Else fallback to coordinate string.
 *
 * @param {{
 *   latitude: number,
 *   longitude: number,
 *   addressText?: string | null,
 *   source?: string | null,
 * }} params
 * @returns {Promise<{ addressText: string, source: string | null }>}
 */
export async function deriveAddressAndSourceForLocation(params) {
  const trimmed = String(params.addressText ?? "").trim();
  if (trimmed.length > 0) {
    return {
      addressText: trimmed,
      source: params.source ?? null,
    };
  }

  const reverse = await reverseGeocodeBarikoi({
    latitude: params.latitude,
    longitude: params.longitude,
  });
  const geocoded = reverse.place?.address?.trim();
  if (geocoded) {
    return {
      addressText: geocoded,
      source: "api_geocoded",
    };
  }

  return {
    addressText: toCoordFallback(params.latitude, params.longitude),
    source: params.source ?? null,
  };
}
