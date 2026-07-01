import {
  distanceKmSql,
  orderByDistanceAscSql,
} from "../config/sqlDialect.js";

export { distanceKmSql, orderByDistanceAscSql };

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
