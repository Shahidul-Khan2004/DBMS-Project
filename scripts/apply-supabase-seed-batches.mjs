#!/usr/bin/env node
/**
 * Apply prepared NIERS seed SQL batches to Supabase/Postgres.
 * Usage: SUPABASE_DB_URL='postgresql://...' node scripts/apply-supabase-seed-batches.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

const connectionString = process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;
if (!connectionString?.startsWith('postgres')) {
  console.error('Set SUPABASE_DB_URL or DATABASE_URL to a postgres connection string.');
  process.exit(1);
}

const batchDir = process.env.SEED_BATCH_DIR || '/tmp/admin_batches';
const files = fs.readdirSync(batchDir).filter((f) => f.startsWith('batch_') && f.endsWith('.sql')).sort();

const client = new pg.Client({ connectionString, ssl: { rejectUnauthorized: false } });
await client.connect();

for (const file of files) {
  const sql = fs.readFileSync(path.join(batchDir, file), 'utf8');
  process.stdout.write(`Applying ${file} (${sql.length} bytes)... `);
  try {
    await client.query(sql);
    console.log('ok');
  } catch (err) {
    console.log('FAILED');
    console.error(err.message);
    process.exit(1);
  }
}

await client.end();
console.log(`Applied ${files.length} batch files from ${batchDir}`);
