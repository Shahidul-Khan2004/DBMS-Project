import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import mysql from "mysql2/promise";
import { findUserByEmail } from "../repositories/userRepo.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SEED_DIR = join(__dirname, "../schemas/docker-init");

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

  const conn = await mysql.createConnection({
    user: process.env.MYSQL_USER,
    host: process.env.MYSQL_HOST,
    database: process.env.MYSQL_DATABASE,
    password: process.env.MYSQL_PASSWORD,
    port: Number(process.env.MYSQL_PORT || 3306),
    multipleStatements: false,
  });

  try {
    for (const file of SEED_FILES) {
      const sql = readFileSync(join(SEED_DIR, file), "utf8");
      const statements = splitSqlStatements(sql);
      for (const statement of statements) {
        await conn.query(`${statement};`);
      }
    }
    console.log("Operational demo seeds applied (29–33).");
  } catch (err) {
    console.error("Operational demo seed failed:", err.message);
    throw err;
  } finally {
    await conn.end();
  }
}
