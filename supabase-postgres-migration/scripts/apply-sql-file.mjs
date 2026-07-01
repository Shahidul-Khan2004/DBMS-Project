#!/usr/bin/env node
/**
 * Apply a .sql file to Postgres using DATABASE_URL or SUPABASE_DB_URL.
 * Usage: DATABASE_URL='postgresql://...' node apply-sql-file.mjs path/to/file.sql
 */
import fs from "fs";
import pg from "pg";

const file = process.argv[2];
if (!file) {
  console.error("Usage: DATABASE_URL=postgresql://... node apply-sql-file.mjs <file.sql>");
  process.exit(1);
}

const url = process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;
if (!url?.startsWith("postgres")) {
  console.error("Set DATABASE_URL or SUPABASE_DB_URL to a postgresql:// connection string.");
  process.exit(1);
}

const sql = fs.readFileSync(file, "utf8");
const client = new pg.Client({
  connectionString: url,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
});

await client.connect();
try {
  await client.query(sql);
  console.log(`Applied ${file} (${sql.length} bytes)`);
} finally {
  await client.end();
}
