import pool from "../config/db.js";

/**
 * Prefix search for district or upazila with hierarchy path.
 * @param {{ areaType: 'district'|'upazila', q: string, limit?: number }} params
 */
export async function searchAdministrativeAreas(params) {
  const q = String(params.q ?? "").trim();
  if (!q) return [];
  const limit = Math.min(Math.max(Number(params.limit) || 20, 1), 50);
  const pattern = `${q}%`;
  const areaType = params.areaType;

  if (areaType === "district") {
    const [rows] = await pool.execute(
      `
        SELECT
          d.id,
          d.code,
          d.name,
          d.area_type AS areaType,
          CONCAT(d.name, ', ', division.name) AS hierarchyPath
        FROM administrative_areas d
        INNER JOIN administrative_areas division ON division.id = d.parent_area_id
        WHERE d.area_type = 'district'
          AND d.name LIKE ?
        ORDER BY d.name
        LIMIT ${limit}
      `,
      [pattern],
    );
    return rows.map(mapRow);
  }

  const [rows] = await pool.execute(
    `
      SELECT
        u.id,
        u.code,
        u.name,
        u.area_type AS areaType,
        CONCAT(u.name, ', ', d.name, ', ', division.name) AS hierarchyPath
      FROM administrative_areas u
      INNER JOIN administrative_areas d ON d.id = u.parent_area_id
      INNER JOIN administrative_areas division ON division.id = d.parent_area_id
      WHERE u.area_type = 'upazila'
        AND u.name LIKE ?
      ORDER BY u.name
      LIMIT ${limit}
    `,
    [pattern],
  );
  return rows.map(mapRow);
}

function mapRow(row) {
  return {
    id: Number(row.id),
    code: row.code,
    name: row.name,
    areaType: row.areaType,
    hierarchyPath: row.hierarchyPath,
  };
}

/**
 * @param {import("mysql2/promise").PoolConnection} conn
 * @param {number} districtAdminAreaId
 * @returns {Promise<number[]>}
 */
export async function listUpazilaIdsUnderDistrict(conn, districtAdminAreaId) {
  const [district] = await conn.execute(
    `
      SELECT id, area_type
      FROM administrative_areas
      WHERE id = ?
      LIMIT 1
    `,
    [districtAdminAreaId],
  );
  if (!district[0] || district[0].area_type !== "district") {
    return null;
  }
  const [rows] = await conn.execute(
    `
      SELECT id
      FROM administrative_areas
      WHERE parent_area_id = ? AND area_type = 'upazila'
    `,
    [districtAdminAreaId],
  );
  return rows.map((r) => Number(r.id));
}
