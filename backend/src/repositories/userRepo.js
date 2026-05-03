import { query } from "../config/db.js";
import pool from "../config/db.js";

export async function findUserByEmail(email) {
  const result = await query(
    `
      SELECT
        u.id,
        u.public_uuid,
        u.email,
        up.full_name,
        u.password_hash,
        up.phone_number,
        (u.account_status = 'active') AS is_active,
        u.created_at,
        u.updated_at
      FROM users u
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE u.email = ?
    `,
    [email]
  );

  return result.rows[0] || null;
}

export async function findUserByPublicUuid(publicUuid) {
  const result = await query(
    `
      SELECT
        u.id,
        u.public_uuid,
        u.email,
        up.full_name,
        u.password_hash,
        up.phone_number,
        (u.account_status = 'active') AS is_active,
        u.created_at,
        u.updated_at
      FROM users u
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE u.public_uuid = ?
    `,
    [publicUuid]
  );

  return result.rows[0] || null;
}

export async function findUserById(userId) {
  const result = await query(
    `
      SELECT
        u.id,
        u.public_uuid,
        u.email,
        up.full_name,
        u.password_hash,
        up.phone_number,
        (u.account_status = 'active') AS is_active,
        u.created_at,
        u.updated_at
      FROM users u
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE u.id = ?
    `,
    [userId]
  );

  return result.rows[0] || null;
}

export async function createUser({ publicUuid, email, fullName, phoneNumber, passwordHash }) {
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [userInsertResult] = await connection.query(
      `
        INSERT INTO users (public_uuid, email, password_hash, account_status)
        VALUES (?, ?, ?, 'active')
      `,
      [publicUuid, email, passwordHash]
    );

    await connection.query(
      `
        INSERT INTO user_profiles (user_id, full_name, phone_number)
        VALUES (?, ?, ?)
      `,
      [userInsertResult.insertId, fullName, phoneNumber ?? null]
    );

    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}
