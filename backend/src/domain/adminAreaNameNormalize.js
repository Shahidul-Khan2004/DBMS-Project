/**
 * Normalize administrative / geocoder place names for comparison.
 */

/** @type {readonly [string, string][]} — ordered replacements on collapsed ascii */
const ASCII_SYNONYMS = [
  ["chittagong", "chattogram"],
  ["jessore", "jashore"],
  ["comilla", "cumilla"],
  ["coxs bazar", "coxsbazar"],
  ["cox's bazar", "coxsbazar"],
  ["cox bazar", "coxsbazar"],
  ["barisal", "barishal"],
  ["bogra", "bogura"],
];

/** Bidirectional spelling variants (matching only; not applied in `normalizeAdministrativeAreaName`). */
const MATCH_EXPAND_PAIRS = [
  ["chattogram", "chattagram"],
  ["cumilla", "comilla"],
];

/**
 * Lowercase, trim, remove punctuation/apostrophes, collapse whitespace.
 * @param {string | null | undefined} raw
 * @returns {string}
 */
export function normalizeAdministrativeAreaName(raw) {
  if (raw == null) return "";
  let s = String(raw).trim().toLowerCase();
  s = s.normalize("NFKD").replace(/\p{M}/gu, "");
  s = s.replace(/['’`]/g, "");
  s = s.replace(/[^\p{L}\p{N}\s]/gu, " ");
  s = s.replace(/\s+/g, " ").trim();
  for (const [from, to] of ASCII_SYNONYMS) {
    if (s.includes(from)) s = s.split(from).join(to);
  }
  s = s.replace(/\s+/g, " ").trim();
  return s;
}

/**
 * Keys to try when matching a provider string to DB `administrative_areas.name`.
 * @param {string | null | undefined} raw
 * @returns {string[]}
 */
export function expandNormalizedNameKeys(raw) {
  const base = normalizeAdministrativeAreaName(raw);
  if (!base) return [];
  const out = new Set([base]);
  for (const [a, b] of [...ASCII_SYNONYMS, ...MATCH_EXPAND_PAIRS]) {
    if (base.includes(a)) out.add(base.split(a).join(b));
    if (base.includes(b)) out.add(base.split(b).join(a));
  }
  return [...out];
}

/**
 * @param {string} dbName
 * @param {string[]} keys
 */
export function adminAreaNameMatchesKeys(dbName, keys) {
  const n = normalizeAdministrativeAreaName(dbName);
  if (!n) return false;
  return keys.includes(n);
}
