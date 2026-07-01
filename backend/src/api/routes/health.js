import express from "express";
import { query } from "../../config/db.js";
import { getDbDialect } from "../../config/sqlDialect.js";

const router = express.Router();

function readDatabaseHost() {
  const connectionString =
    process.env.DATABASE_URL || process.env.SUPABASE_DB_URL || "";
  try {
    return new URL(connectionString).hostname || null;
  } catch {
    return null;
  }
}

router.get("/health", async (req, res) => {
  try {
    const result = await query(
      `SELECT
         NOW() AS db_time,
         VERSION() AS db_version,
         current_database() AS db_name,
         (SELECT COUNT(*)::int FROM users WHERE email = 'citizen.rahima@niers.test') AS demo_citizen_count`,
    );
    res.status(200).json({
      status: "RUNNING",
      timestamp: new Date().toLocaleString("en-BD", { timeZone: "Asia/Dhaka" }),
      dbDialect: getDbDialect(),
      dbHost: readDatabaseHost(),
      dbTime: result.rows[0].db_time,
      dbVersion: result.rows[0].db_version,
      dbName: result.rows[0].db_name,
      demoCitizenPresent: Number(result.rows[0].demo_citizen_count) > 0,
    });
  } catch (error) {
    console.error("Health check DB error:", error.message);
    res.status(503).json({
      status: "DEGRADED",
      timestamp: new Date().toLocaleString("en-BD", { timeZone: "Asia/Dhaka" }),
      dbError: error.message,
    });
  }
});

export default router;
