#!/usr/bin/env node
/**
 * Apply storyline seed sub-chunks (a1–a3, b1–b3) in order via Postgres.
 * Usage:
 *   DATABASE_URL='postgresql://...' PGSSLMODE=require \
 *     node apply-storyline-chunks.mjs
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const chunksDir = path.join(__dirname, "../migrations/chunks");
const files = [
  "004_seed_storyline_a1.sql",
  "004_seed_storyline_a2.sql",
  "004_seed_storyline_a3.sql",
  "004_seed_storyline_b1.sql",
  "004_seed_storyline_b2.sql",
  "004_seed_storyline_b3.sql",
];

const url = process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;
if (!url?.startsWith("postgres")) {
  console.error("Set DATABASE_URL or SUPABASE_DB_URL to a postgresql:// connection string.");
  process.exit(1);
}

const client = new pg.Client({
  connectionString: url,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
});

await client.connect();
try {
  for (const file of files) {
    const full = path.join(chunksDir, file);
    const sql = fs.readFileSync(full, "utf8");
    await client.query(sql);
    console.log(`Applied ${file} (${sql.length} bytes)`);
  }
  const { rows } = await client.query(`
    SELECT
      (SELECT COUNT(*) FROM locations WHERE public_uuid = 'a9110001-0000-4000-8000-000000000001') AS fire_loc,
      (SELECT COUNT(*) FROM intake_reports WHERE report_code LIKE 'IR-DHK-FIRE%') AS fire_reports,
      (SELECT COUNT(*) FROM agencies WHERE agency_code = 'DHK-FIRE-01') AS fire_agency,
      (SELECT COUNT(*) FROM facilities WHERE facility_code = 'SHELTER-KUR-01') AS shelter
  `);
  console.log("Verification:", rows[0]);
} finally {
  await client.end();
}
