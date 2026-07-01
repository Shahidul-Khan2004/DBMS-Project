/** @returns {'mysql' | 'postgres'} */
export function getDbDialect() {
  if (process.env.DB_DIALECT === "postgres") {
    return "postgres";
  }
  if (process.env.DATABASE_URL?.startsWith("postgres")) {
    return "postgres";
  }
  return "mysql";
}

export function isPostgres() {
  return getDbDialect() === "postgres";
}

/**
 * Convert `?` placeholders to PostgreSQL `$1..$n` for a single statement.
 * @param {string} sql
 * @param {unknown[]} params
 */
export function toPgParams(sql, params = []) {
  let i = 0;
  const pgSql = sql.replace(/\?/g, () => `$${++i}`);
  return { sql: pgSql, params };
}

/** @param {string} mysqlSql */
export function upsertSuffix(mysqlSql) {
  if (!isPostgres()) {
    return mysqlSql;
  }
  return mysqlSql
    .replace(
      /ON DUPLICATE KEY UPDATE\s+name = VALUES\(name\),\s*description = VALUES\(description\),\s*is_system_role = VALUES\(is_system_role\)/i,
      "ON CONFLICT (role_code) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, is_system_role = EXCLUDED.is_system_role",
    )
    .replace(
      /ON DUPLICATE KEY UPDATE\s+module_name = VALUES\(module_name\),\s*description = VALUES\(description\)/i,
      "ON CONFLICT (permission_code) DO UPDATE SET module_name = EXCLUDED.module_name, description = EXCLUDED.description",
    )
    .replace(
      /ON DUPLICATE KEY UPDATE role_id = VALUES\(role_id\)/i,
      "ON CONFLICT (role_id, permission_id) DO UPDATE SET role_id = EXCLUDED.role_id",
    )
    .replace(
      /ON DUPLICATE KEY UPDATE is_active = TRUE/i,
      "ON CONFLICT (facility_id, capability_id) DO UPDATE SET is_active = TRUE",
    )
    .replace(
      /ON DUPLICATE KEY UPDATE total_capacity = VALUES\(total_capacity\)/i,
      "ON CONFLICT (facility_id, capacity_type) DO UPDATE SET total_capacity = EXCLUDED.total_capacity",
    );
}

/** @param {string} mysqlSql */
export function deleteUserRoleSql(mysqlSql) {
  if (!isPostgres()) {
    return mysqlSql;
  }
  return mysqlSql.replace(
    /DELETE ur FROM user_roles ur\s+INNER JOIN roles r ON r\.id = ur\.role_id\s+WHERE ur\.user_id = \? AND r\.role_code = \?/i,
    `DELETE FROM user_roles ur
      USING roles r
      WHERE r.id = ur.role_id
        AND ur.user_id = ?
        AND r.role_code = ?`,
  );
}

/** @param {string} refAlias @param {string} entityAlias */
export function distanceKmSql(refAlias, entityAlias) {
  if (isPostgres()) {
    return `ST_Distance(${refAlias}.geo_point, ${entityAlias}.geo_point) / 1000`;
  }
  return `ST_Distance_Sphere(${refAlias}.geo_point, ${entityAlias}.geo_point) / 1000`;
}

/** @param {string} distanceExpr @param {string} [entityLocIdExpr] */
export function orderByDistanceAscSql(distanceExpr, entityLocIdExpr = "entity_loc.id") {
  return `(${entityLocIdExpr} IS NULL), ${distanceExpr} ASC`;
}

/** Age in minutes from a timestamp column expression. */
export function ageMinutesSql(columnExpr) {
  if (isPostgres()) {
    return `FLOOR(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - ${columnExpr})) / 60)`;
  }
  return `TIMESTAMPDIFF(MINUTE, ${columnExpr}, CURRENT_TIMESTAMP)`;
}

/** Reference geo join for list sorting when only lat/lng is known. */
export function referenceGeoCrossJoinSql() {
  if (isPostgres()) {
    return "CROSS JOIN (SELECT ST_SetSRID(ST_MakePoint(?, ?), 4326)::geography AS geo_point) ref_geom";
  }
  return "CROSS JOIN (SELECT ST_GeomFromText(CONCAT('POINT(', ?, ' ', ?, ')'), 4326) AS geo_point) ref_geom";
}
