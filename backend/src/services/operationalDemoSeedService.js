import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { findUserByEmail } from "../repositories/userRepo.js";
import pool, { isPostgres } from "../config/db.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SEED_DIR = join(__dirname, "../schemas/docker-init");
const PG_SEED_DIR = join(
  __dirname,
  "../../../supabase-postgres-migration/converted-sql",
);

const SEED_FILES = [
  "29_seed_citizen_reporting_demo.sql",
  "30_seed_pre_disaster_operations_demo.sql",
  "31_seed_case_messages_notifications_demo.sql",
  "32_seed_reporter_risk_demo.sql",
  "33_seed_storyline_demo.sql",
];

const CITIZEN_GATE_EMAIL = "citizen.rahima@niers.test";

function stripLeadingSqlComments(sql) {
  let statement = sql.trim();
  while (statement.startsWith("--")) {
    const newline = statement.indexOf("\n");
    if (newline === -1) {
      return "";
    }
    statement = statement.slice(newline + 1).trim();
  }
  return statement;
}

function splitSqlStatements(sql) {
  if (/^DO\s+\$\$/im.test(sql.trim())) {
    return [sql.trim()];
  }
  return sql
    .split(/;\s*\n/)
    .map((statement) => stripLeadingSqlComments(statement))
    .filter((statement) => statement.length > 0);
}

async function citizensReady() {
  const user = await findUserByEmail(CITIZEN_GATE_EMAIL);
  return Boolean(user);
}

export async function runOperationalDemoSeeds() {
  const password = process.env.DEMO_CITIZEN_PASSWORD;
  if (!password || password.length < 8) {
    return;
  }

  if (!(await citizensReady())) {
    console.warn(
      "Skipping operational demo seeds. Demo citizens not found; ensure DEMO_CITIZEN_PASSWORD bootstrap ran.",
    );
    return;
  }

  const conn = await pool.getConnection();

  try {
    for (const file of SEED_FILES) {
      const path = isPostgres()
        ? join(PG_SEED_DIR, file.replace(".sql", ".pg.sql"))
        : join(SEED_DIR, file);
      const sql = readFileSync(path, "utf8");
      const statements = splitSqlStatements(sql);
      for (const statement of statements) {
        await conn.execute(isPostgres() ? statement : `${statement};`);
      }
    }
    console.log("Operational demo seeds applied (29–33).");
  } catch (err) {
    console.error("Operational demo seed failed:", err.message);
    throw err;
  } finally {
    conn.release();
  }
}
