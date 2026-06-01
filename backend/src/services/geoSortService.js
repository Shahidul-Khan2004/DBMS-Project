import pool from "../config/db.js";
import { resolveReferenceFromQuery } from "../repositories/geoReferenceRepo.js";

/**
 * @param {Record<string, unknown>} query validated query
 * @param {object} [options]
 * @param {string} [options.disasterPublicUuid]
 * @param {number | null} [options.actorUserId]
 * @returns {Promise<{ geoSort: null | { ref: import('../repositories/geoReferenceRepo.js').GeoReference, includeDistance: boolean } }>}
 */
export async function resolveGeoSortFromQuery(query, options = {}) {
  if (query.sort !== "distance_asc") {
    return { geoSort: null };
  }

  const ref = await resolveReferenceFromQuery(pool, query, options);
  return {
    geoSort: {
      ref,
      includeDistance: query.includeDistance === true,
    },
  };
}

/**
 * @param {Record<string, unknown>} filters
 * @param {{ geoSort: null | { ref: object, includeDistance: boolean } }} geo
 */
export function mergeGeoSortIntoFilters(filters, geo) {
  if (!geo.geoSort) {
    return filters;
  }
  return {
    ...filters,
    geoSort: geo.geoSort,
  };
}
