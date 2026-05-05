import pool, { query } from "../config/db.js";

// New users are inserted with this status so they can log in immediately. The `users` table default
// in schema.sql is `pending_verification`; change this constant (and docs) if you require activation first.
const REGISTRATION_ACCOUNT_STATUS = "active";

const userSelect = `
  SELECT
    u.id,
    u.public_uuid,
    u.email,
    u.password_hash,
    u.account_status,
    u.created_at,
    u.updated_at,
    up.full_name,
    up.phone_number
  FROM users u
  LEFT JOIN user_profiles up ON up.user_id = u.id
`;

export async function findUserByEmail(email) {
  const result = await query(`${userSelect} WHERE u.email = ?`, [email]);
  return result.rows[0] || null;
}

export async function findUserByPublicUuid(publicUuid) {
  const result = await query(`${userSelect} WHERE u.public_uuid = ?`, [
    publicUuid,
  ]);
  return result.rows[0] || null;
}

export async function createUser({ publicUuid, email, fullName, phoneNumber, passwordHash }) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [userResult] = await conn.execute(
      `
        INSERT INTO users (public_uuid, email, password_hash, account_status)
        VALUES (?, ?, ?, ?)
      `,
      [publicUuid, email, passwordHash, REGISTRATION_ACCOUNT_STATUS]
    );
    const userId = userResult.insertId;
    await conn.execute(
      `
        INSERT INTO user_profiles (user_id, full_name, phone_number)
        VALUES (?, ?, ?)
      `,
      [userId, fullName, phoneNumber]
    );
    await conn.commit();
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}
