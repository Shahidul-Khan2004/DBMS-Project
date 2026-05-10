#!/usr/bin/env node
/**
 * Maintainer-only: fetches MIT-licensed data from nuhil/bangladesh-geocode (GitHub raw)
 * and writes backend/src/schemas/docker-init/22_seed_administrative_areas.sql
 *
 * Source: https://github.com/nuhil/bangladesh-geocode (see third_party/bangladesh-geocode/LICENSE)
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "../src/schemas/docker-init/22_seed_administrative_areas.sql");
const BASE =
  "https://raw.githubusercontent.com/nuhil/bangladesh-geocode/master";

function extractTableRows(json, tableName) {
  for (const entry of json) {
    if (entry?.type === "table" && entry?.name === tableName && Array.isArray(entry.data)) {
      return entry.data;
    }
  }
  throw new Error(`Table "${tableName}" not found in JSON export`);
}

async function loadJson(path) {
  const url = `${BASE}/${path}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Fetch failed ${res.status}: ${url}`);
  return res.json();
}

function esc(s) {
  if (s == null) return "";
  return String(s).replace(/\\/g, "\\\\").replace(/'/g, "''").trim().slice(0, 150);
}

function divCode(id) {
  return `BD-DIV-${id}`;
}
function distCode(id) {
  return `BD-DIST-${id}`;
}
function upzCode(id) {
  return `BD-UPZ-${id}`;
}
function unionCode(id) {
  return `BD-UNION-${id}`;
}

/** MySQL disallows `INSERT … SELECT` from the same table without a derived wrapper (ER 1093). */
function parentIdSubquery(code) {
  return `(SELECT id FROM (SELECT id FROM administrative_areas WHERE code = '${code}' LIMIT 1) AS _aa_p)`;
}

/** Satisfy UNIQUE(parent_area_id, area_type, name) when source has duplicate names. */
function makeNameDeduper() {
  const counts = new Map();
  return (parentKey, baseName, stableId) => {
    const key = `${parentKey}\0${baseName}`;
    const n = (counts.get(key) || 0) + 1;
    counts.set(key, n);
    if (n === 1) return baseName;
    const suffix = ` #${stableId}`;
    const combined = `${baseName}${suffix}`;
    return combined.length <= 150 ? combined : `${baseName.slice(0, 150 - suffix.length)}${suffix}`;
  };
}

async function main() {
  const [divisionsJ, districtsJ, upazilasJ, unionsJ] = await Promise.all([
    loadJson("divisions/divisions.json"),
    loadJson("districts/districts.json"),
    loadJson("upazilas/upazilas.json"),
    loadJson("unions/unions.json"),
  ]);

  const divisions = extractTableRows(divisionsJ, "divisions");
  const districts = extractTableRows(districtsJ, "districts");
  const upazilas = extractTableRows(upazilasJ, "upazilas");
  const unions = extractTableRows(unionsJ, "unions");

  const nameDistrict = makeNameDeduper();
  const nameUpazila = makeNameDeduper();
  const nameUnion = makeNameDeduper();

  const lines = [];
  lines.push("-- Administrative areas: Bangladesh hierarchy (division → district → upazila → union)");
  lines.push("-- Data source: https://github.com/nuhil/bangladesh-geocode (MIT). Codes are stable IDs from that dataset.");
  lines.push("");

  for (const d of divisions) {
    const code = divCode(d.id);
    lines.push(
      `INSERT INTO administrative_areas (parent_area_id, area_type, name, code) VALUES (NULL, 'division', '${esc(d.name)}', '${code}');`,
    );
  }

  for (const d of districts) {
    const pcode = divCode(d.division_id);
    const nm = nameDistrict(pcode, String(d.name).trim(), d.id);
    lines.push(
      `INSERT INTO administrative_areas (parent_area_id, area_type, name, code) VALUES (${parentIdSubquery(pcode)}, 'district', '${esc(nm)}', '${distCode(d.id)}');`,
    );
  }

  for (const u of upazilas) {
    const pcode = distCode(u.district_id);
    const nm = nameUpazila(pcode, String(u.name).trim(), u.id);
    lines.push(
      `INSERT INTO administrative_areas (parent_area_id, area_type, name, code) VALUES (${parentIdSubquery(pcode)}, 'upazila', '${esc(nm)}', '${upzCode(u.id)}');`,
    );
  }

  for (const u of unions) {
    const pid = u["upazilla_id"];
    const parentCode = upzCode(pid);
    const nm = nameUnion(parentCode, String(u.name).trim(), u.id);
    lines.push(
      `INSERT INTO administrative_areas (parent_area_id, area_type, name, code) VALUES (${parentIdSubquery(parentCode)}, 'union', '${esc(nm)}', '${unionCode(u.id)}');`,
    );
  }

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, `${lines.join("\n")}\n`, "utf8");
  console.error(
    `Wrote ${OUT} (${divisions.length} divisions, ${districts.length} districts, ${upazilas.length} upazilas, ${unions.length} unions)`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
