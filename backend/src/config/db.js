import mysql from "mysql2/promise";
import pg from "pg";
import { isPostgres, toPgParams } from "./sqlDialect.js";

function isInsert(sql) {
  return /^\s*INSERT\b/i.test(sql);
}

function insertTargetTable(sql) {
  const match = sql.match(/INSERT\s+INTO\s+(?:ONLY\s+)?(?:public\.)?["']?(\w+)["']?/i);
  return match?.[1]?.toLowerCase() ?? null;
}

function withReturningId(sql) {
  if (!isPostgres() || !isInsert(sql) || /\bRETURNING\b/i.test(sql)) {
    return sql;
  }
  const table = insertTargetTable(sql);
  // No surrogate `id` column — callers do not need insertId for these inserts.
  if (table === "user_profiles") {
    return sql;
  }
  return `${sql.replace(/;\s*$/, "")} RETURNING id`;
}

function normalizeResult(driverResult, sql) {
  if (isPostgres()) {
    const result = driverResult;
    const rows = result.rows ?? [];
    return {
      rows,
      insertId: rows[0]?.id ?? rows[0]?.user_id ?? null,
      affectedRows: result.rowCount ?? 0,
    };
  }

  const [rows, fields] = driverResult;
  const header =
    rows && typeof rows === "object" && !Array.isArray(rows) ? rows : fields;
  return {
    rows: Array.isArray(rows) ? rows : [],
    insertId: header?.insertId ?? null,
    affectedRows: header?.affectedRows ?? 0,
  };
}

/** mysql2 returns OkPacket as 1st element for INSERT; repos read `result.insertId`. */
function executeFirstTuple(normalized, sql) {
  if (isInsert(sql) && normalized.insertId != null) {
    return {
      insertId: normalized.insertId,
      affectedRows: normalized.affectedRows,
    };
  }
  return normalized.rows;
}

async function runOnClient(client, text, params) {
  if (isPostgres()) {
    const { sql, params: pgParams } = toPgParams(withReturningId(text), params);
    return client.query(sql, pgParams);
  }
  return client.query(text, params);
}

function wrapClient(client) {
  return {
    async execute(text, params) {
      const driverResult = await runOnClient(client, text, params);
      const normalized = normalizeResult(driverResult, text);
      return [executeFirstTuple(normalized, text), normalized];
    },
    async query(text, params) {
      return runOnClient(client, text, params);
    },
    async beginTransaction() {
      if (isPostgres()) {
        await client.query("BEGIN");
      } else {
        await client.beginTransaction();
      }
    },
    async commit() {
      if (isPostgres()) {
        await client.query("COMMIT");
      } else {
        await client.commit();
      }
    },
    async rollback() {
      if (isPostgres()) {
        await client.query("ROLLBACK");
      } else {
        await client.rollback();
      }
    },
    release() {
      client.release();
    },
  };
}

function createMysqlPool() {
  const mysqlPool = mysql.createPool({
    user: process.env.MYSQL_USER,
    host: process.env.MYSQL_HOST,
    database: process.env.MYSQL_DATABASE,
    password: process.env.MYSQL_PASSWORD,
    port: Number(process.env.MYSQL_PORT || 3306),
    waitForConnections: true,
    connectionLimit: 20,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    connectTimeout: 10000,
  });

  return {
    async query(text, params) {
      try {
        const driverResult = await mysqlPool.query(text, params);
        const normalized = normalizeResult(driverResult, text);
        return { rows: normalized.rows, ...normalized };
      } catch (err) {
        console.error("Query Error", err.message, err.stack);
        throw err;
      }
    },
    async execute(text, params) {
      const driverResult = await mysqlPool.query(text, params);
      const normalized = normalizeResult(driverResult, text);
      return [executeFirstTuple(normalized, text), normalized];
    },
    async getConnection() {
      const conn = await mysqlPool.getConnection();
      return wrapClient(conn);
    },
  };
}

function createPostgresPool() {
  const connectionString =
    process.env.DATABASE_URL || process.env.SUPABASE_DB_URL;
  if (!connectionString) {
    throw new Error(
      "PostgreSQL selected but DATABASE_URL or SUPABASE_DB_URL is not set.",
    );
  }

  const pgPool = new pg.Pool({
    connectionString,
    ssl:
      process.env.PGSSLMODE === "disable"
        ? false
        : { rejectUnauthorized: false },
    max: Number(process.env.PG_POOL_MAX || 5),
    idleTimeoutMillis: Number(process.env.PG_POOL_IDLE_MS || 30_000),
    connectionTimeoutMillis: Number(process.env.PG_POOL_CONNECT_MS || 10_000),
  });

  return {
    async query(text, params) {
      try {
        const driverResult = await runOnClient(pgPool, text, params);
        const normalized = normalizeResult(driverResult, text);
        return { rows: normalized.rows, ...normalized };
      } catch (err) {
        console.error("Query Error", err.message, err.stack);
        throw err;
      }
    },
    async execute(text, params) {
      const driverResult = await runOnClient(pgPool, text, params);
      const normalized = normalizeResult(driverResult, text);
      return [executeFirstTuple(normalized, text), normalized];
    },
    async getConnection() {
      const client = await pgPool.connect();
      return wrapClient(client);
    },
  };
}

const pool = isPostgres() ? createPostgresPool() : createMysqlPool();

export async function query(text, params) {
  return pool.query(text, params);
}

export { isPostgres } from "./sqlDialect.js";
export default pool;
