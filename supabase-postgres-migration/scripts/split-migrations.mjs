import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "../migrations/chunks");
mkdirSync(OUT, { recursive: true });

const MAX = 80000;

function chunkSql(sql, baseName) {
  const parts = sql.split(/\n(?=-- from )/);
  const chunks = [];
  let current = "";
  for (const part of parts) {
    const next = current ? `${current}\n${part}` : part;
    if (next.length > MAX && current) {
      chunks.push(current);
      current = part;
    } else {
      current = next;
    }
  }
  if (current.trim()) chunks.push(current);
  chunks.forEach((chunk, i) => {
    const outName = `${baseName}_chunk${String(i + 1).padStart(2, "0")}.sql`;
    if (chunk.length <= MAX) {
      writeFileSync(join(OUT, outName), chunk);
      console.log(outName, chunk.length);
      return;
    }
    const statements = chunk.split(/;\s*\n/);
    let sub = "";
    let subIdx = 0;
    for (const stmt of statements) {
      const piece = stmt.trim();
      if (!piece) continue;
      const next = sub ? `${sub};\n\n${piece}` : piece;
      if (next.length > MAX && sub) {
        writeFileSync(
          join(OUT, `${baseName}_chunk${String(i + 1).padStart(2, "0")}_${String(++subIdx).padStart(2, "0")}.sql`),
          `${sub};`,
        );
        console.log(`${baseName}_chunk${String(i + 1).padStart(2, "0")}_${String(subIdx).padStart(2, "0")}.sql`, sub.length);
        sub = piece;
      } else {
        sub = next;
      }
    }
    if (sub.trim()) {
      writeFileSync(
        join(OUT, `${baseName}_chunk${String(i + 1).padStart(2, "0")}_${String(++subIdx).padStart(2, "0")}.sql`),
        sub.endsWith(";") ? sub : `${sub};`,
      );
      console.log(`${baseName}_chunk${String(i + 1).padStart(2, "0")}_${String(subIdx).padStart(2, "0")}.sql`, sub.length);
    }
  });
}

function chunkFile(name) {
  const sql = readFileSync(join(__dirname, `../migrations/${name}`), "utf8");
  if (name === "004_seed_data.sql") {
    chunkSql(sql, name.replace(".sql", ""));
    return;
  }
  const parts = sql.split(/\n(?=CREATE )/);
  const chunks = [];
  let current = "";
  for (const part of parts) {
    const next = current ? `${current}\n${part}` : part;
    if (next.length > MAX && current) {
      chunks.push(current);
      current = part;
    } else {
      current = next;
    }
  }
  if (current.trim()) chunks.push(current);
  chunks.forEach((chunk, i) => {
    const outName = `${name.replace(".sql", "")}_chunk${String(i + 1).padStart(2, "0")}.sql`;
    writeFileSync(join(OUT, outName), chunk);
    console.log(outName, chunk.length);
  });
}

for (const f of [
  "001_schema.sql",
  "002_triggers.sql",
  "003_views.sql",
  "004_seed_data.sql",
]) {
  chunkFile(f);
}
