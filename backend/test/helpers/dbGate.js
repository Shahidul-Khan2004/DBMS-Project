export const HAS_DB_CONFIG = Boolean(process.env.MYSQL_DATABASE || process.env.DATABASE_URL);

let connectionChecked = false;
let connectionAvailable = false;

/** True when DB env is set and a connection succeeds. */
export async function isDbAvailable() {
  if (!HAS_DB_CONFIG) {
    return false;
  }
  if (connectionChecked) {
    return connectionAvailable;
  }

  connectionChecked = true;
  try {
    const { default: pool } = await import("../../src/config/db.js");
    await pool.query("SELECT 1");
    connectionAvailable = true;
  } catch {
    connectionAvailable = false;
  }
  return connectionAvailable;
}

/** @deprecated use isDbAvailable() in before() hooks */
export const HAS_DB = HAS_DB_CONFIG;

export function integrationSkipMessage() {
  return "Set MYSQL_DATABASE (or DATABASE_URL), start backend Docker MySQL, and configure backend/.env before integration tests.";
}

/** Use as describe options when DB is required: `{ skip: integrationDescribeSkip(!dbUp) }` */
export function integrationDescribeSkip(skip) {
  return skip ? integrationSkipMessage() : false;
}
