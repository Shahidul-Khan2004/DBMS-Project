/**
 * MySQL distance helpers using locations.geo_point (SRID 4326).
 */

/**
 * @param {string} refAlias SQL table alias for reference location
 * @param {string} entityAlias SQL table alias for entity location
 */
export function distanceKmSql(refAlias, entityAlias) {
  return `ST_Distance_Sphere(${refAlias}.geo_point, ${entityAlias}.geo_point) / 1000`;
}

/**
 * @param {string} distanceExpr SQL expression (e.g. from distanceKmSql)
 * @param {string} [entityLocIdExpr] expression that is NULL when entity has no location
 */
export function orderByDistanceAscSql(distanceExpr, entityLocIdExpr = "entity_loc.id") {
  return `(${entityLocIdExpr} IS NULL), ${distanceExpr} ASC`;
}

/**
 * @param {unknown} value
 * @returns {number | null}
 */
export function roundDistanceKm(value) {
  if (value == null || Number.isNaN(Number(value))) {
    return null;
  }
  return Math.round(Number(value) * 1000) / 1000;
}

/**
 * @param {object} row
 * @param {string} [column]
 * @returns {number | null}
 */
export function distanceKmFromRow(row, column = "distance_km_sort") {
  return roundDistanceKm(row[column]);
}

/**
 * @param {object} item mapped list row
 * @param {number | null} distanceKm
 * @param {boolean} includeDistance
 */
export function attachDistanceKm(item, distanceKm, includeDistance) {
  if (!includeDistance) {
    return item;
  }
  return { ...item, distance_km: distanceKm };
}
