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

/** @param {{ parentCode: string | null, areaType: string, name: string, code: string }[]} rows */
function emitDivisionValuesInsert(lines, rows) {
  lines.push("INSERT INTO administrative_areas (parent_area_id, area_type, name, code) VALUES");
  lines.push(
    rows
      .map((r) => `  (NULL, '${r.areaType}', '${esc(r.name)}', '${r.code}')`)
      .join(",\n"),
  );
  lines.push(";");
  lines.push("");
}

/** @param {{ parentCode: string, areaType: string, name: string, code: string }[]} rows */
function emitInsertSelect(lines, rows) {
  if (rows.length === 0) return;
  lines.push("INSERT INTO administrative_areas (parent_area_id, area_type, name, code)");
  lines.push("SELECT p.id, v.area_type, v.name, v.code");
  lines.push("FROM (");
  lines.push(
    rows
      .map(
        (r, i) =>
          `  SELECT '${r.parentCode}' AS parent_code, '${r.areaType}' AS area_type, '${esc(r.name)}' AS name, '${r.code}' AS code${i < rows.length - 1 ? "\n  UNION ALL" : ""}`,
      )
      .join("\n"),
  );
  lines.push(") AS v");
  lines.push("INNER JOIN administrative_areas p ON p.code = v.parent_code;");
  lines.push("");
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

  const divisionRows = divisions.map((d) => ({
    parentCode: null,
    areaType: "division",
    name: String(d.name).trim(),
    code: divCode(d.id),
  }));

  const districtRows = districts.map((d) => {
    const parentCode = divCode(d.division_id);
    return {
      parentCode,
      areaType: "district",
      name: nameDistrict(parentCode, String(d.name).trim(), d.id),
      code: distCode(d.id),
    };
  });

  const upazilaRows = upazilas.map((u) => {
    const parentCode = distCode(u.district_id);
    return {
      parentCode,
      areaType: "upazila",
      name: nameUpazila(parentCode, String(u.name).trim(), u.id),
      code: upzCode(u.id),
    };
  });

  const unionRows = unions.map((u) => {
    const parentCode = upzCode(u["upazilla_id"]);
    return {
      parentCode,
      areaType: "union",
      name: nameUnion(parentCode, String(u.name).trim(), u.id),
      code: unionCode(u.id),
    };
  });

  const lines = [];
  lines.push("-- Administrative areas: Bangladesh hierarchy (division → district → upazila → union)");
  lines.push("-- Data source: https://github.com/nuhil/bangladesh-geocode (MIT). Codes are stable IDs from that dataset.");
  lines.push("-- Bulk inserts (4 statements) for fast Docker init.");
  lines.push("");
  lines.push("SET SESSION unique_checks = 0;");
  lines.push("");

  emitDivisionValuesInsert(lines, divisionRows);
  emitInsertSelect(lines, districtRows);
  emitInsertSelect(lines, upazilaRows);
  emitInsertSelect(lines, unionRows);

  lines.push("SET SESSION unique_checks = 1;");

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
