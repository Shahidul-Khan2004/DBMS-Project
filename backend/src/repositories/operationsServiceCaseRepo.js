import { query } from "../config/db.js";

const OPEN_CASE_JOIN = `
  FROM service_cases sc
  INNER JOIN report_categories rc ON rc.id = sc.category_id AND rc.is_active = TRUE
  INNER JOIN case_statuses cs ON cs.id = sc.current_status_id
`;

/** Non-terminal cases (same semantics as vw_admin_case_queue WHERE cs.is_terminal = FALSE). */
const OPEN_CASE_WHERE = "WHERE cs.is_terminal = FALSE";

/**
 * Count of service_cases whose current_status is non-terminal.
 */
export async function countOpenServiceCases() {
  const { rows } = await query(
    `
      SELECT COUNT(*) AS cnt
      ${OPEN_CASE_JOIN}
      ${OPEN_CASE_WHERE}
    `,
    [],
  );
  const cnt = rows[0]?.cnt;
  return typeof cnt === "bigint" ? Number(cnt) : Number(cnt ?? 0);
}

/**
 * Most recent open service cases for dispatcher overview (includes public_uuid for API symmetry).
 */
export async function listRecentOpenServiceCasesForOperations(limit) {
  const capped = Math.min(Math.max(Number(limit) || 10, 1), 50);

  const { rows } = await query(
    `
      SELECT
        sc.public_uuid AS public_uuid,
        sc.title AS title,
        cs.status_code AS status_code,
        rc.category_code AS category_code,
        sc.created_at AS created_at,
        TIMESTAMPDIFF(MINUTE, sc.created_at, CURRENT_TIMESTAMP) AS age_minutes
      ${OPEN_CASE_JOIN}
      ${OPEN_CASE_WHERE}
      ORDER BY sc.created_at DESC
      LIMIT ?
    `,
    [capped],
  );

  return rows.map((row) => ({
    public_uuid: row.public_uuid,
    title: row.title,
    status_code: row.status_code,
    category_code: row.category_code,
    created_at: row.created_at,
    age_minutes: Number(row.age_minutes ?? 0),
  }));
}
