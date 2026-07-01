#!/usr/bin/env node
/**
 * Converts 33_seed_storyline_demo.sql (MySQL) to PostgreSQL for Supabase.
 * Does NOT modify the original MySQL file.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "../..");
const MYSQL_FILE = join(ROOT, "backend/src/schemas/docker-init/33_seed_storyline_demo.sql");
const OUT_DIR = join(ROOT, "supabase-postgres-migration/converted-sql");
const OUT_FILE = join(OUT_DIR, "33_seed_storyline_demo.pg.sql");
const CHUNK_FILE = join(ROOT, "supabase-postgres-migration/migrations/chunks/004_seed_data_chunk04.sql");

function convertStorylineMysqlToPg(sql) {
  let s = sql;

  // Strip MySQL-only preamble / transaction wrappers
  s = s.replace(/\/\*[\s\S]*?\*\//g, (block) => {
    if (block.includes("NIERS Storyline")) {
      return `-- ${block.replace(/\/\*+|\*+\//g, "").trim().split("\n").join("\n-- ")}\n`;
    }
    return block;
  });
  s = s.replace(/SET\s+NAMES\s+\w+;?/gi, "");
  s = s.replace(/SET\s+time_zone\s*=[^;]+;?/gi, "");
  s = s.replace(/START\s+TRANSACTION;?/gi, "");
  s = s.replace(/COMMIT;?/gi, "");

  s = s.replace(/`/g, "");
  s = s.replace(
    /\bST_SRID\s*\(\s*POINT\s*\(\s*([^)]+)\s*\)\s*,\s*4326\s*\)/gi,
    "ST_SetSRID(ST_MakePoint($1), 4326)::geography",
  );
  s = s.replace(
    /NOW\s*\(\s*\)\s*-\s*INTERVAL\s+(\d+)\s+(\w+)/gi,
    (_, n, unit) => `NOW() - INTERVAL '${n} ${unit.toLowerCase().replace(/s$/, "")}'`,
  );

  s = s.replace(/\bINSERT\s+IGNORE\s+INTO\b/gi, "INSERT INTO");

  // Reference inserts: add ON CONFLICT DO NOTHING
  for (const table of [
    "report_channels",
    "report_categories",
    "agency_types",
    "capabilities",
    "emergency_unit_types",
    "disaster_event_types",
    "facility_types",
    "relief_items",
  ]) {
    s = s.replace(
      new RegExp(`(INSERT INTO ${table}[\\s\\S]*?);`, "gi"),
      (m) => (m.includes("ON CONFLICT") ? m : `${m.replace(/;\s*$/, "")} ON CONFLICT DO NOTHING;`),
    );
  }

  // Agency memberships upsert
  s = s.replace(
    /ON\s+DUPLICATE\s+KEY\s+UPDATE\s+membership_status\s*=\s*'active',\s*membership_role\s*=\s*VALUES\(membership_role\),\s*left_at\s*=\s*NULL/gi,
    "ON CONFLICT (user_id, agency_id) DO UPDATE SET membership_status = 'active', membership_role = EXCLUDED.membership_role, left_at = NULL",
  );

  // Collect session variables
  const varNames = new Map();
  s = s.replace(
    /SET\s+@(\w+)\s*=\s*([^;]+);/gis,
    (_, name, expr) => {
      const pgName = `v_${name}`;
      varNames.set(name, pgName);
      let pgExpr = expr.trim();
      if (pgExpr.startsWith("(") && pgExpr.endsWith(")")) {
        const inner = pgExpr.slice(1, -1).trim();
        if (/^SELECT\b/i.test(inner)) {
          return `${inner} INTO ${pgName};`;
        }
        pgExpr = inner;
      }
      if (/^SELECT\b/i.test(pgExpr)) {
        return `${pgExpr} INTO ${pgName};`;
      }
      return `${pgName} := ${pgExpr};`;
    },
  );

  for (const [mysql, pg] of varNames) {
    s = s.replace(new RegExp(`@${mysql}\\b`, "g"), pg);
  }

  // FROM DUAL patterns
  s = s.replace(/\s+FROM\s+DUAL\s+WHERE/gi, "\nWHERE");
  s = s.replace(/\s+FROM\s+DUAL\s*;/gi, ";");
  s = s.replace(/\s+FROM\s+DUAL\s*$/gim, "");
  s = s.replace(/\s+FROM\s+DUAL\s+ON\s+CONFLICT/gi, "\nON CONFLICT");

  // Fix broken INTO from bad prior conversion
  s = s.replace(/\) ON CONFLICT DO NOTHING INTO/gi, ") INTO");
  s = s.replace(/LIMIT 1\) ON CONFLICT DO NOTHING/gi, "LIMIT 1");
  s = s.replace(/WHERE NOT EXISTS \([^)]+\) ON CONFLICT DO NOTHING/gi, (m) =>
    m.replace(" ON CONFLICT DO NOTHING", ""),
  );

  const declares = [...new Set(varNames.values())]
    .map((v) => `  ${v} BIGINT;`)
    .join("\n");

  const body = s
    .split("\n")
    .map((line) => {
      const t = line.trim();
      if (!t || t.startsWith("--")) return line;
      return `  ${line}`;
    })
    .join("\n");

  return `DO $$
DECLARE
${declares}
BEGIN
${body}
END $$;
`;
}

mkdirSync(OUT_DIR, { recursive: true });
const mysql = readFileSync(MYSQL_FILE, "utf8");
const pg = convertStorylineMysqlToPg(mysql);
writeFileSync(OUT_FILE, pg);
writeFileSync(CHUNK_FILE, `-- PostgreSQL storyline demo (from 33_seed_storyline_demo.sql)\n${pg}`);
console.log(`Wrote ${OUT_FILE}`);
console.log(`Wrote ${CHUNK_FILE} (${pg.length} bytes)`);
