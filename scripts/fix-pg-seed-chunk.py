#!/usr/bin/env python3
"""Fix PostgreSQL seed chunk SQL and split for MCP apply."""
import re
import sys
from pathlib import Path

CHUNKS_DIR = Path(__file__).resolve().parents[1] / "supabase-postgres-migration/migrations/chunks"
OUT_DIR = Path("/tmp/seed_apply_fixed")


def fix_admin_chunk(sql: str) -> str:
    """Add ON CONFLICT (code) DO NOTHING to administrative_areas INSERT...SELECT."""
    parts = re.split(r"(?=INSERT INTO administrative_areas)", sql, flags=re.IGNORECASE)
    out = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if not re.match(r"INSERT INTO administrative_areas", part, re.I):
            out.append(part)
            continue
        if "ON CONFLICT" not in part.upper():
            part = re.sub(
                r"(INNER JOIN administrative_areas p ON p\.code = v\.parent_code)\s*;",
                r"\1\nON CONFLICT (code) DO NOTHING;",
                part,
                flags=re.I,
            )
        out.append(part)
    return "\n\n".join(out)


def fix_seed_chunk(sql: str) -> str:
    """Fix common MySQL->PG conversion issues in demo seed chunks."""
    s = sql

    # Remove FROM DUAL remnants
    s = re.sub(r"\bFROM\s+DUAL\b", "", s, flags=re.I)

    # Fix ON CONFLICT wrongly appended to JOIN/WHERE lines
    s = re.sub(
        r"(INNER JOIN\s+\w+\s+\w+\s+ON\s+[^;\n]+)\s+ON CONFLICT DO NOTHING\s*;",
        r"\1;",
        s,
        flags=re.I,
    )
    s = re.sub(
        r"(WHERE\s+[^;\n]+)\s+ON CONFLICT DO NOTHING\s*;",
        r"\1;",
        s,
        flags=re.I,
    )
    s = re.sub(
        r"(AND NOT EXISTS\s*\([^)]+\))\s+ON CONFLICT DO NOTHING\s*;",
        r"\1;",
        s,
        flags=re.I,
    )

    # Fix mangled subquery endings: LIMIT 1) ON CONFLICT
    s = re.sub(
        r"(LIMIT\s+1)\)\s+ON CONFLICT DO NOTHING\s*;",
        r"\1);",
        s,
        flags=re.I,
    )

    # MySQL DELETE alias FROM -> DELETE FROM ... USING
    s = re.sub(
        r"DELETE\s+(\w+)\s+FROM\s+(\w+)\s+(\w+)\s+",
        r"DELETE FROM \2 \3 USING \2 \3 ",
        s,
        flags=re.I,
    )

    # Strip ON CONFLICT from comment-only lines
    s = re.sub(r"(--[^\n]*)\s+ON CONFLICT DO NOTHING\s*;", r"\1;", s)

    # Fix INSERT...SELECT with JOIN - move ON CONFLICT to statement end
    def fix_insert_join(m):
        stmt = m.group(0)
        if "ON CONFLICT" in stmt and re.search(r"JOIN[^;]+ON CONFLICT", stmt, re.I):
            stmt = re.sub(r"\s+ON CONFLICT DO NOTHING\s*;", ";", stmt)
            if not stmt.rstrip().endswith("ON CONFLICT"):
                stmt = stmt.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING;"
        return stmt

    s = re.sub(
        r"INSERT INTO[\s\S]*?INNER JOIN[\s\S]*?;",
        fix_insert_join,
        s,
        flags=re.I,
    )

    return s


def split_statements(sql: str, max_bytes: int = 14000) -> list[str]:
    """Split on INSERT/DO/DELETE boundaries keeping under max_bytes."""
    parts = re.split(
        r"(?=(?:INSERT INTO|DO \$\$|DELETE FROM|UPDATE ))",
        sql,
        flags=re.I,
    )
    chunks: list[str] = []
    current = ""
    for part in parts:
        if not part.strip():
            continue
        if len(current) + len(part) > max_bytes and current:
            chunks.append(current.strip())
            current = part
        else:
            current += part
    if current.strip():
        chunks.append(current.strip())
    return chunks


def process_file(src: Path, out_prefix: str, admin: bool = False) -> list[Path]:
    sql = src.read_text(encoding="utf-8")
    fixed = fix_admin_chunk(sql) if admin else fix_seed_chunk(sql)
    stmts = split_statements(fixed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    paths = []
    for i, stmt in enumerate(stmts, 1):
        p = OUT_DIR / f"{out_prefix}_part{i:02d}.sql"
        p.write_text(stmt, encoding="utf-8")
        paths.append(p)
    return paths


def main():
    files = sys.argv[1:] if len(sys.argv) > 1 else []
    if not files:
        print("Usage: fix-pg-seed-chunk.py <chunk_file> ...")
        sys.exit(1)
    for f in files:
        src = Path(f)
        admin = "chunk02" in src.name
        prefix = src.stem.replace("004_seed_data_", "")
        paths = process_file(src, prefix, admin=admin)
        print(f"{src.name}: {len(paths)} parts, {sum(p.stat().st_size for p in paths)} bytes")


if __name__ == "__main__":
    main()
