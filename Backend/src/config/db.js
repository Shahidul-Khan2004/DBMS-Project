import mysql from "mysql2/promise";
import "dotenv/config";

const pool = mysql.createPool({
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

export async function query(text, params) {
  try {
    const [rows] = await pool.query(text, params);

    return { rows };
  } catch (err) {
    console.error("Query Error", err.message, err.stack);
    throw err;
  }
}

export default pool;
