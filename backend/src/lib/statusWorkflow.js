import BackendError from "./BackendError.js";

const STATUS_TABLES = {
  case: "case_statuses",
  incident: "incident_statuses",
  intake: "intake_statuses",
  dispatch: "dispatch_statuses",
  unit: "unit_statuses",
  disaster: "disaster_event_statuses",
  relief_request: "relief_request_statuses",
};

const TRANSITION_TABLES = {
  case: "case_status_transitions",
  incident: "incident_status_transitions",
  intake: "intake_status_transitions",
  dispatch: "dispatch_status_transitions",
  unit: "unit_status_transitions",
  disaster: "disaster_event_status_transitions",
  relief_request: "relief_request_status_transitions",
};

export async function findStatusIdByCode(conn, domain, statusCode) {
  const table = STATUS_TABLES[domain];
  if (!table) {
    throw new Error(`Unknown status domain: ${domain}`);
  }
  const [rows] = await conn.execute(
    `
      SELECT id, is_terminal
      FROM ${table}
      WHERE status_code = ? AND is_active = TRUE
      LIMIT 1
    `,
    [statusCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "INVALID_STATUS_CODE", `Invalid status code: ${statusCode}`);
  }
  return { id: rows[0].id, isTerminal: Boolean(rows[0].is_terminal) };
}

export async function assertStatusTransitionAllowed(
  conn,
  domain,
  fromStatusCode,
  toStatusCode,
  { note = null, outcomeId = null } = {},
) {
  if (!fromStatusCode || !toStatusCode) {
    throw new BackendError(422, "INVALID_STATUS_CODE", "Invalid status transition");
  }
  if (fromStatusCode === toStatusCode) {
    throw new BackendError(
      409,
      "INVALID_STATUS_TRANSITION",
      "Status is already set to the requested value",
    );
  }

  const from = await findStatusIdByCode(conn, domain, fromStatusCode);
  const to = await findStatusIdByCode(conn, domain, toStatusCode);

  if (from.isTerminal) {
    throw new BackendError(
      409,
      "INVALID_STATUS_TRANSITION",
      "Cannot change status from a terminal state",
    );
  }

  const transitionTable = TRANSITION_TABLES[domain];
  const selectColumns =
    domain === "incident" ? "requires_note, requires_outcome" : "requires_note";
  const [rows] = await conn.execute(
    `
      SELECT ${selectColumns}
      FROM ${transitionTable}
      WHERE from_status_id = ?
        AND to_status_id = ?
        AND is_active = TRUE
      LIMIT 1
    `,
    [from.id, to.id],
  );

  if (!rows[0]) {
    throw new BackendError(
      409,
      "INVALID_STATUS_TRANSITION",
      `Cannot transition from '${fromStatusCode}' to '${toStatusCode}'`,
    );
  }

  if (rows[0].requires_note && (!note || !String(note).trim())) {
    throw new BackendError(422, "NOTE_REQUIRED", "Status transition requires a note");
  }

  if (domain === "incident" && rows[0].requires_outcome && !outcomeId) {
    throw new BackendError(422, "OUTCOME_REQUIRED", "Status transition requires an outcome");
  }

  return { fromStatusId: from.id, toStatusId: to.id };
}
