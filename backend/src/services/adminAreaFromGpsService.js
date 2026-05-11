import { reverseGeocodeBarikoi } from "../integrations/barikoiReverseGeocoder.js";
import BackendError from "../lib/BackendError.js";
import {
  adminAreaNameMatchesKeys,
  expandNormalizedNameKeys,
} from "../domain/adminAreaNameNormalize.js";
import { listAdministrativeAreasByTypeUnderParents } from "../repositories/administrativeAreaRepo.js";

/**
 * @param {{ id: number, name: string }[]} rows
 * @param {string | null | undefined} providerName
 */
function pickHits(rows, providerName) {
  const keys = expandNormalizedNameKeys(providerName);
  if (!keys.length) return [];
  return rows.filter((r) => adminAreaNameMatchesKeys(r.name, keys));
}

/**
 * @typedef {object} AdminAreaGpsResolution
 * @property {number} adminAreaId
 * @property {'union'|'upazila'|'district'|'division'} matchedLevel
 * @property {'high'|'medium'} confidence
 * @property {unknown} providerPayload
 */

/**
 * Reverse geocode with Barikoi and match to `administrative_areas.id`.
 * Returns null when provider fails, names are missing, or matching is ambiguous.
 *
 * @param {import("mysql2/promise").Pool} pool
 * @param {number} latitude
 * @param {number} longitude
 * @param {{
 *   fetchFn?: typeof fetch
 *   barikoiApiKey?: string | null
 *   listAdministrativeAreasByTypeUnderParents?: typeof listAdministrativeAreasByTypeUnderParents
 * }} [deps]
 * @returns {Promise<AdminAreaGpsResolution | null>}
 */
export async function resolveAdminAreaFromCoordinates(pool, latitude, longitude, deps = {}) {
  const listAreas =
    deps.listAdministrativeAreasByTypeUnderParents ??
    listAdministrativeAreasByTypeUnderParents;

  const bg = await reverseGeocodeBarikoi({
    latitude,
    longitude,
    fetchFn: deps.fetchFn,
    apiKey: deps.barikoiApiKey,
  });
  if (bg.authOrQuotaFailure) {
    const { kind, httpStatus, providerMessage } = bg.authOrQuotaFailure;
    const details = { httpStatus, providerMessage: providerMessage ?? null };
    if (kind === "quota") {
      throw new BackendError(
        503,
        "BARIKOI_QUOTA_EXCEEDED",
        "Barikoi rate or usage limit was reached. Replace or upgrade BARIKOI_API_KEY, or retry later.",
        details,
      );
    }
    throw new BackendError(
      503,
      "BARIKOI_API_KEY_REJECTED",
      "Barikoi rejected the API key (invalid or expired). Set a valid BARIKOI_API_KEY.",
      details,
    );
  }
  const p = bg.place;
  const hasSignal =
    p.division ||
    p.district ||
    p.upazila ||
    p.union ||
    p.city ||
    p.area ||
    p.thana ||
    p.address;
  if (!hasSignal) {
    return null;
  }

  const divisionRows = await listAreas(pool, "division", null);

  let divisionScopeIds;
  if (p.division) {
    const divHits = pickHits(divisionRows, p.division);
    if (divHits.length === 1) {
      divisionScopeIds = [divHits[0].id];
    } else {
      divisionScopeIds = divisionRows.map((r) => r.id);
    }
  } else {
    divisionScopeIds = divisionRows.map((r) => r.id);
  }

  const districtLabel = p.district || p.city;
  if (!districtLabel) {
    if (!p.division) return null;
    const divOnly = pickHits(divisionRows, p.division);
    if (divOnly.length !== 1) return null;
    return {
      adminAreaId: divOnly[0].id,
      matchedLevel: "division",
      confidence: "medium",
      providerPayload: bg.providerPayload,
    };
  }

  const districtRows = await listAreas(pool, "district", divisionScopeIds);
  const distHits = pickHits(districtRows, districtLabel);
  if (distHits.length !== 1) {
    return null;
  }
  const districtId = distHits[0].id;

  let singleUpazilaId = null;
  if (p.upazila) {
    const upazilaRows = await listAreas(pool, "upazila", [districtId]);
    const uHits = pickHits(upazilaRows, p.upazila);
    if (uHits.length > 1) {
      return null;
    }
    if (uHits.length === 1) {
      singleUpazilaId = uHits[0].id;
    }
  }

  if (p.union && singleUpazilaId != null) {
    const unionRows = await listAreas(pool, "union", [singleUpazilaId]);
    const uniHits = pickHits(unionRows, p.union);
    if (uniHits.length > 1) {
      return null;
    }
    if (uniHits.length === 1) {
      return {
        adminAreaId: uniHits[0].id,
        matchedLevel: "union",
        confidence: "high",
        providerPayload: bg.providerPayload,
      };
    }
  }

  if (singleUpazilaId != null) {
    return {
      adminAreaId: singleUpazilaId,
      matchedLevel: "upazila",
      confidence: "high",
      providerPayload: bg.providerPayload,
    };
  }

  return {
    adminAreaId: districtId,
    matchedLevel: "district",
    confidence: "high",
    providerPayload: bg.providerPayload,
  };
}

/**
 * @typedef {object} AdminAreaResolutionMeta
 * @property {boolean} adminAreaResolved
 * @property {string | null} adminAreaMatchedLevel
 */

/**
 * When `explicitAdminAreaId` is set, skips Barikoi entirely.
 *
 * @param {object} opts
 * @param {number | null | undefined} opts.explicitAdminAreaId
 * @param {number} opts.latitude
 * @param {number} opts.longitude
 * @param {import("mysql2/promise").Pool} opts.pool
 * @param {typeof fetch} [opts.fetchFn]
 * @param {string | null} [opts.barikoiApiKey]
 * @param {Function} [opts.listAdministrativeAreasByTypeUnderParents] — inject for tests
 * @returns {Promise<{ adminAreaId: number | null, resolutionMeta: AdminAreaResolutionMeta }>}
 */
export async function resolveAdminAreaIdForLocationPayload(opts) {
  if (opts.explicitAdminAreaId != null) {
    return {
      adminAreaId: Number(opts.explicitAdminAreaId),
      resolutionMeta: {
        adminAreaResolved: false,
        adminAreaMatchedLevel: null,
      },
    };
  }

  const resolved = await resolveAdminAreaFromCoordinates(
    opts.pool,
    opts.latitude,
    opts.longitude,
    {
      fetchFn: opts.fetchFn,
      barikoiApiKey: opts.barikoiApiKey,
      listAdministrativeAreasByTypeUnderParents:
        opts.listAdministrativeAreasByTypeUnderParents,
    },
  );

  if (!resolved) {
    return {
      adminAreaId: null,
      resolutionMeta: {
        adminAreaResolved: false,
        adminAreaMatchedLevel: null,
      },
    };
  }

  return {
    adminAreaId: resolved.adminAreaId,
    resolutionMeta: {
      adminAreaResolved: true,
      adminAreaMatchedLevel: resolved.matchedLevel,
    },
  };
}
