import {
  distanceKmSql,
  orderByDistanceAscSql,
  referenceGeoCrossJoinSql,
} from "../config/sqlDialect.js";

/**
 * @typedef {{ locationId: number | null, latitude: number, longitude: number }} GeoReference
 */

/**
 * @param {GeoReference} ref
 * @returns {{ joinSql: string, params: Array<number>, distanceExpr: string }}
 */
export function buildReferenceJoin(ref) {
  if (ref.locationId != null) {
    return {
      joinSql: "INNER JOIN locations ref_loc ON ref_loc.id = ?",
      params: [ref.locationId],
      distanceExpr: distanceKmSql("ref_loc", "entity_loc"),
    };
  }
  return {
    joinSql: referenceGeoCrossJoinSql(),
    params: [ref.longitude, ref.latitude],
    distanceExpr: distanceKmSql("ref_geom", "entity_loc"),
  };
}

/**
 * @param {GeoReference} ref
 * @param {string} [entityLocIdExpr]
 */
export function buildDistanceSortClause(ref, entityLocIdExpr = "entity_loc.id") {
  const { joinSql, params, distanceExpr } = buildReferenceJoin(ref);
  return {
    joinSql,
    joinParams: params,
    selectDistanceSql: `${distanceExpr} AS distance_km_sort`,
    orderBySql: orderByDistanceAscSql(distanceExpr, entityLocIdExpr),
  };
}
