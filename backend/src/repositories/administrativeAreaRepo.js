/**
 * Read helpers for `administrative_areas` (GPS / resolver matching).
 * @param {import("mysql2/promise").Pool} pool
 */

/**
 * @param {import("mysql2/promise").Pool} pool
 * @param {'division'|'district'|'upazila'|'union'} areaType
 * @param {number[] | null} parentIds — `null` or empty only for division roots
 * @returns {Promise<{ id: number, parent_area_id: number | null, name: string }[]>}
 */
export async function listAdministrativeAreasByTypeUnderParents(pool, areaType, parentIds) {
  if (areaType === "division") {
    const [rows] = await pool.execute(
      `
        SELECT id, parent_area_id, name
        FROM administrative_areas
        WHERE area_type = 'division' AND parent_area_id IS NULL
        ORDER BY id
      `,
    );
    return rows.map((r) => ({
      id: Number(r.id),
      parent_area_id: r.parent_area_id != null ? Number(r.parent_area_id) : null,
      name: String(r.name),
    }));
  }

  if (!parentIds?.length) {
    return [];
  }

  const placeholders = parentIds.map(() => "?").join(",");
  const [rows] = await pool.execute(
    `
      SELECT id, parent_area_id, name
      FROM administrative_areas
      WHERE area_type = ? AND parent_area_id IN (${placeholders})
      ORDER BY id
    `,
    [areaType, ...parentIds],
  );
  return rows.map((r) => ({
    id: Number(r.id),
    parent_area_id: r.parent_area_id != null ? Number(r.parent_area_id) : null,
    name: String(r.name),
  }));
}

/**
 * @param {import("mysql2/promise").Pool} pool
 * @param {number} adminAreaId
 * @returns {Promise<string | null>}
 */
export async function getAdministrativeAreaLabelById(pool, adminAreaId) {
  const [rows] = await pool.execute(
    `
      SELECT
        CASE
          WHEN aa.id IS NULL THEN NULL
          WHEN aa.area_type = 'upazila' THEN CONCAT(aa.name, ', ', d_aa.name, ', ', div_aa.name)
          WHEN aa.area_type = 'district' THEN CONCAT(aa.name, ', ', div_aa.name)
          ELSE aa.name
        END AS adminAreaLabel
      FROM administrative_areas aa
      LEFT JOIN administrative_areas d_aa ON d_aa.id = aa.parent_area_id
      LEFT JOIN administrative_areas div_aa ON div_aa.id = d_aa.parent_area_id
      WHERE aa.id = ?
      LIMIT 1
    `,
    [adminAreaId],
  );
  return rows[0]?.adminAreaLabel ?? null;
}

function mapAreaNode(row) {
  return {
    id: Number(row.id),
    name: String(row.name),
    code: String(row.code),
    areaType: String(row.area_type),
  };
}

/**
 * Full administrative hierarchy for a single area id (division → district → upazila → union).
 * @param {import("mysql2/promise").Pool} pool
 * @param {number} adminAreaId
 */
export async function getAdministrativeAreaDetailById(pool, adminAreaId) {
  const [rows] = await pool.execute(
    `
      WITH RECURSIVE ancestors AS (
        SELECT id, parent_area_id, area_type, name, code, 0 AS depth
        FROM administrative_areas
        WHERE id = ?
        UNION ALL
        SELECT aa.id, aa.parent_area_id, aa.area_type, aa.name, aa.code, a.depth + 1
        FROM administrative_areas aa
        INNER JOIN ancestors a ON aa.id = a.parent_area_id
      )
      SELECT id, parent_area_id, area_type, name, code, depth
      FROM ancestors
      ORDER BY depth DESC
    `,
    [adminAreaId],
  );
  if (!rows.length) {
    return null;
  }

  const chain = rows.map(mapAreaNode);
  const target = chain[chain.length - 1];
  const byType = Object.fromEntries(chain.map((node) => [node.areaType, node]));
  const hierarchyNames = chain
    .filter((node) =>
      ["division", "district", "upazila", "union"].includes(node.areaType),
    )
    .map((node) => node.name);

  return {
    id: target.id,
    code: target.code,
    name: target.name,
    areaType: target.areaType,
    hierarchyPath: hierarchyNames.join(", "),
    division: byType.division ?? null,
    district: byType.district ?? null,
    upazila: byType.upazila ?? null,
    union: byType.union ?? null,
  };
}
