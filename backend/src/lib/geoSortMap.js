import { attachDistanceKm, distanceKmFromRow } from "./geoDistance.js";

/**
 * @param {object} item
 * @param {object} row
 * @param {{ includeDistance?: boolean } | null | undefined} geoSort
 */
export function mapRowWithOptionalDistance(item, row, geoSort) {
  if (!geoSort?.includeDistance) {
    return item;
  }
  return attachDistanceKm(item, distanceKmFromRow(row), true);
}
