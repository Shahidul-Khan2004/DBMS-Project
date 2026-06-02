/**
 * Shared audit log writer for transactional workflows.
 * @param {import("mysql2/promise").PoolConnection} conn
 */
export async function insertAuditLog(conn, params) {
  const detailsJson =
    params.detailsJson == null ? null : JSON.stringify(params.detailsJson);
  await conn.execute(
    `
      INSERT INTO audit_logs (
        actor_user_id,
        action,
        entity_type,
        entity_id,
        related_incident_id,
        related_case_id,
        related_disaster_event_id,
        details_json,
        ip_address,
        user_agent
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      params.actorUserId ?? null,
      params.action,
      params.entityType,
      params.entityId,
      params.relatedIncidentId ?? null,
      params.relatedCaseId ?? null,
      params.relatedDisasterEventId ?? null,
      detailsJson,
      params.ipAddress ?? null,
      params.userAgent ?? null,
    ],
  );
}

export function auditMetaFromRequest(req) {
  return {
    ipAddress: req.ip ?? null,
    userAgent:
      typeof req.get === "function" ? (req.get("user-agent") ?? null) : null,
  };
}
