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
