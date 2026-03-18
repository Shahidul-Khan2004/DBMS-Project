import express from "express";
import { query } from "../../config/db.js";

const router = express.Router();

router.get("/health", async (req, res) => {
  try {
    const result = await query(
      "SELECT NOW() AS db_time, VERSION() AS db_version;"
    );
    res.status(200).json({
      status: "RUNNING",
      timestamp: new Date().toLocaleString("en-BD", { timeZone: "Asia/Dhaka" }),
      dbTime: result.rows[0].db_time,
      dbVersion: result.rows[0].db_version,
    });
  } catch (err) {
    console.error("Health Check Error", err.message, err.stack);
    res.status(500).json({
      status: "ERROR",
      message: "Database connection failed",
    });
  }
});

export default router;
