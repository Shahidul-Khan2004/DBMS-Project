import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { findUserByEmail } from "../repositories/userRepo.js";
import pool, { isPostgres, query } from "../config/db.js";

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

async function showcaseDataAlreadySeeded() {
  if (!isPostgres()) {
    return false;
  }
  const result = await query(
    "SELECT 1 AS ok FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-001' LIMIT 1",
  );
  return Boolean(result.rows[0]);
}

export async function runOperationalDemoSeeds() {
  const password = process.env.DEMO_CITIZEN_PASSWORD;
  if (!password || password.length < 8) {
    return;
  }

  if (process.env.SKIP_OPERATIONAL_DEMO_SEEDS === "true") {
    console.log(
      "Skipping operational demo seeds (SKIP_OPERATIONAL_DEMO_SEEDS=true).",
    );
    return;
  }

  if (!(await citizensReady())) {
    console.warn(
      "Skipping operational demo seeds. Demo citizens not found; ensure DEMO_CITIZEN_PASSWORD bootstrap ran.",
    );
    return;
  }

  if (await showcaseDataAlreadySeeded()) {
    console.log(
      "Skipping operational demo seeds (showcase data already present in database).",
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
    console.warn(
      "Operational demo seed skipped after error (non-fatal on deploy):",
      err.message,
    );
  } finally {
    conn.release();
  }
}
