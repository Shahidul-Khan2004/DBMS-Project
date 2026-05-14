/**
 * Barikoi reverse geocoding (Bangladesh-focused).
 * @see https://docs.barikoi.com/api/ — GET /v2/api/search/reverse/geocode
 */

const DEFAULT_BASE_URL = "https://barikoi.xyz/v2/api/search/reverse/geocode";
const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * @typedef {object} BarikoiPlaceNormalized
 * @property {string | null} division
 * @property {string | null} district
 * @property {string | null} upazila — sub_district from API
 * @property {string | null} union
 * @property {string | null} city
 * @property {string | null} area
 * @property {string | null} thana
 * @property {string | null} address
 * @property {object | null} rawPlace
 */

/**
 * @typedef {'invalid_key' | 'quota'} BarikoiAuthOrQuotaKind
 */

/**
 * @typedef {object} BarikoiAuthOrQuotaFailure
 * @property {BarikoiAuthOrQuotaKind} kind
 * @property {number} httpStatus
 * @property {string | undefined} providerMessage
 */

/**
 * @typedef {object} BarikoiSearchPlaceResult
 * @property {string | null} placeCode
 * @property {string | null} address
 * @property {string | null} name
 * @property {string | null} city
 * @property {string | null} area
 * @property {string | null} latitude
 * @property {string | null} longitude
 * @property {unknown} rawPlace
 *
 * @typedef {object} BarikoiReverseGeocodeResult
 * @property {BarikoiPlaceNormalized} place
 * @property {number | null} httpStatus
 * @property {unknown} providerPayload — parsed JSON body when object
 * @property {BarikoiAuthOrQuotaFailure | null} authOrQuotaFailure — set when Barikoi signals invalid key or quota
 */

/**
 * Detect invalid/expired API key or usage / rate limit from HTTP status or JSON `status` (when HTTP is still 200).
 *
 * @param {number | null} httpStatus
 * @param {unknown} providerPayload
 * @returns {BarikoiAuthOrQuotaFailure | null}
 */
export function classifyBarikoiAuthOrQuotaFailure(httpStatus, providerPayload) {
  if (httpStatus === 401 || httpStatus === 403) {
    return {
      kind: "invalid_key",
      httpStatus,
      providerMessage: extractProviderMessage(providerPayload),
    };
  }
  if (httpStatus === 429 || httpStatus === 402) {
    return {
      kind: "quota",
      httpStatus,
      providerMessage: extractProviderMessage(providerPayload),
    };
  }

  if (providerPayload && typeof providerPayload === "object") {
    const p = /** @type {Record<string, unknown>} */ (providerPayload);
    const bodyStatus = typeof p.status === "number" ? p.status : null;
    if (bodyStatus === 401 || bodyStatus === 403) {
      return {
        kind: "invalid_key",
        httpStatus: httpStatus ?? bodyStatus,
        providerMessage: extractProviderMessage(providerPayload),
      };
    }
    if (bodyStatus === 429 || bodyStatus === 402) {
      return {
        kind: "quota",
        httpStatus: httpStatus ?? bodyStatus,
        providerMessage: extractProviderMessage(providerPayload),
      };
    }
  }

  return null;
}

/**
 * @param {unknown} providerPayload
 * @returns {string | undefined}
 */
function extractProviderMessage(providerPayload) {
  if (!providerPayload || typeof providerPayload !== "object") return undefined;
  const p = /** @type {Record<string, unknown>} */ (providerPayload);
  for (const key of ["message", "msg", "error"]) {
    const v = p[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

/**
 * @param {unknown} v
 * @returns {string | null}
 */
function pickString(v) {
  if (v == null) return null;
  const s = String(v).trim();
  return s.length ? s : null;
}

/**
 * @param {object} place
 * @returns {BarikoiPlaceNormalized}
 */
export function normalizeBarikoiPlace(place) {
  if (!place || typeof place !== "object") {
    return {
      division: null,
      district: null,
      upazila: null,
      union: null,
      city: null,
      area: null,
      thana: null,
      address: null,
      rawPlace: place ?? null,
    };
  }
  const p = /** @type {Record<string, unknown>} */ (place);
  return {
    division: pickString(p.division),
    district: pickString(p.district),
    upazila: pickString(p.sub_district ?? p.subDistrict),
    union: pickString(p.union),
    city: pickString(p.city),
    area: pickString(p.area),
    thana: pickString(p.thana),
    address: pickString(p.address),
    rawPlace: place,
  };
}

function parseBarikoiNumber(value) {
  if (value == null) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function normalizeBarikoiSearchPlace(place) {
  if (!place || typeof place !== "object") {
    return null;
  }

  const p = /** @type {Record<string, unknown>} */ (place);
  const latitude = parseBarikoiNumber(p.latitude ?? p.lat);
  const longitude = parseBarikoiNumber(p.longitude ?? p.lon);
  if (latitude === null || longitude === null) {
    return null;
  }

  const address = pickString(p.address);
  const name = pickString(p.name);
  const label = address || name ||
    [pickString(p.area), pickString(p.city), pickString(p.thana)]
      .filter(Boolean)
      .join(", ") ||
    "Matched map location";

  return {
    placeCode: pickString(p.place_code ?? p.uCode),
    address,
    name,
    city: pickString(p.city),
    area: pickString(p.area),
    latitude: String(latitude),
    longitude: String(longitude),
    rawPlace: place,
    label,
  };
}

/**
 * @typedef {object} BarikoiSearchResult
 * @property {string} id
 * @property {number} latitude
 * @property {number} longitude
 * @property {string} label
 * @property {string | null} addressText
 * @property {string | null} placeName
 * @property {unknown} rawPlace
 */

/**
 * @param {object} opts
 * @param {string} opts.query
 * @param {number} [opts.limit]
 * @param {typeof fetch} [opts.fetchFn] — for tests
 * @param {string} [opts.apiKey] — defaults to process.env.BARIKOI_API_KEY
 * @param {string} [opts.baseUrl] — override full endpoint URL
 * @param {number} [opts.timeoutMs]
 * @returns {Promise<{places: BarikoiSearchResult[]; httpStatus: number | null; providerPayload: unknown; authOrQuotaFailure: BarikoiAuthOrQuotaFailure | null;}>>
 */
export async function searchPlacesBarikoi(opts) {
  const apiKey = opts.apiKey ?? process.env.BARIKOI_API_KEY;
  const fetchFn = opts.fetchFn ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const baseUrl = opts.baseUrl ?? "https://barikoi.xyz/v2/api/search/autocomplete/place";

  if (!apiKey || !fetchFn) {
    return {
      places: [],
      httpStatus: null,
      providerPayload: null,
      authOrQuotaFailure: null,
    };
  }

  const params = new URLSearchParams({
    api_key: String(apiKey),
    q: String(opts.query),
    country_code: "bd",
    bangla: "false",
  });

  const url = `${baseUrl}?${params.toString()}`;

  try {
    const res = await fetchFn(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const httpStatus = res.status;
    let body;
    try {
      body = await res.json();
    } catch {
      body = null;
    }

    const authOrQuotaFailure = classifyBarikoiAuthOrQuotaFailure(httpStatus, body);
    const rawPlaces =
      body && typeof body === "object" && Array.isArray(body.places)
        ? body.places
        : [];

    const places = rawPlaces
      .map(normalizeBarikoiSearchPlace)
      .filter((result) => result !== null)
      .map((result, index) => ({
        id:
          result.placeCode ||
          `${result.latitude}-${result.longitude}-${index}`,
        latitude: Number(result.latitude),
        longitude: Number(result.longitude),
        label: result.label,
        addressText: result.address || undefined,
        placeName: result.name || undefined,
        rawPlace: result.rawPlace,
      }));

    return {
      places: typeof opts.limit === "number" ? places.slice(0, opts.limit) : places,
      httpStatus,
      providerPayload: body,
      authOrQuotaFailure,
    };
  } catch {
    return {
      places: [],
      httpStatus: null,
      providerPayload: null,
      authOrQuotaFailure: null,
    };
  }
}

/**
 * Reverse geocode coordinates. Returns normalized place fields; on failure returns empty place.
 *
 * @param {object} opts
 * @param {number} opts.latitude
 * @param {number} opts.longitude
 * @param {typeof fetch} [opts.fetchFn] — for tests
 * @param {string} [opts.apiKey] — defaults to process.env.BARIKOI_API_KEY
 * @param {string} [opts.baseUrl] — override full endpoint URL
 * @param {number} [opts.timeoutMs]
 * @returns {Promise<BarikoiReverseGeocodeResult>}
 */
export async function reverseGeocodeBarikoi(opts) {
  const apiKey = opts.apiKey ?? process.env.BARIKOI_API_KEY;
  const fetchFn = opts.fetchFn ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;

  if (!apiKey || !fetchFn) {
    return {
      place: normalizeBarikoiPlace(null),
      httpStatus: null,
      providerPayload: null,
      authOrQuotaFailure: null,
    };
  }

  const lat = Number(opts.latitude);
  const lng = Number(opts.longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return {
      place: normalizeBarikoiPlace(null),
      httpStatus: null,
      providerPayload: null,
      authOrQuotaFailure: null,
    };
  }

  const params = new URLSearchParams({
    api_key: String(apiKey),
    longitude: String(lng),
    latitude: String(lat),
    district: "true",
    sub_district: "true",
    union: "true",
    division: "true",
    address: "true",
    area: "true",
    city: "true",
    thana: "true",
    bangla: "false",
  });

  const url = `${baseUrl}?${params.toString()}`;

  try {
    const res = await fetchFn(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const httpStatus = res.status;
    let body;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    const placeRaw =
      body && typeof body === "object" && "place" in body ? /** @type {any} */ (body).place : null;
    const authOrQuotaFailure = classifyBarikoiAuthOrQuotaFailure(httpStatus, body);
    return {
      place: normalizeBarikoiPlace(placeRaw),
      httpStatus,
      providerPayload: body,
      authOrQuotaFailure,
    };
  } catch {
    return {
      place: normalizeBarikoiPlace(null),
      httpStatus: null,
      providerPayload: null,
      authOrQuotaFailure: null,
    };
  }
}
