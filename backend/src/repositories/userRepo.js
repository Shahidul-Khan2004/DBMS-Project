import pool, { query } from "../config/db.js";

// New users are inserted with this status so they can log in immediately. The `users` table default
// in docker-init seed is `pending_verification`; change this constant (and docs) if you require activation first.
const REGISTRATION_ACCOUNT_STATUS = "active";

const userSelect = `
  SELECT
    u.id,
    u.public_uuid,
    u.email,
    u.password_hash,
    u.account_status,
    u.account_status_reason,
    u.account_status_expires_at,
    u.created_at,
    u.updated_at,
    up.full_name,
    up.phone_number,
    up.secondary_phone_number
  FROM users u
  LEFT JOIN user_profiles up ON up.user_id = u.id
`;

export async function findUserByEmail(email) {
  const normalizedEmail = email.trim().toLowerCase();
  const result = await query(`${userSelect} WHERE LOWER(u.email) = ?`, [
    normalizedEmail,
  ]);
  return result.rows[0] || null;
}

export async function findUserByPublicUuid(publicUuid) {
  const result = await query(`${userSelect} WHERE u.public_uuid = ?`, [
    publicUuid,
  ]);
  return result.rows[0] || null;
}

export async function findUserById(userId) {
  const result = await query(`${userSelect} WHERE u.id = ?`, [userId]);
  return result.rows[0] || null;
}

export async function updateUserProfile(userId, { fullName, phoneNumber, secondaryPhoneNumber }) {
  const setClauses = [];
  const values = [];

  if (fullName !== undefined) {
    setClauses.push("full_name = ?");
    values.push(fullName);
  }
  if (phoneNumber !== undefined) {
    setClauses.push("phone_number = ?");
    values.push(phoneNumber);
  }
  if (secondaryPhoneNumber !== undefined) {
    setClauses.push("secondary_phone_number = ?");
    values.push(secondaryPhoneNumber); // null is allowed
  }

  if (setClauses.length === 0) {
    throw new Error("updateUserProfile: no fields to update");
  }

  values.push(userId);

  const [result] = await pool.execute(
    `UPDATE user_profiles SET ${setClauses.join(", ")} WHERE user_id = ?`,
    values,
  );

  if (result.affectedRows === 0) {
    return null; // profile row missing
  }

  return findUserById(userId);
}

export async function updateUserPasswordHash(userId, passwordHash) {
  const result = await query(
    `UPDATE users SET password_hash = ? WHERE id = ?`,
    [passwordHash, userId],
  );
  const affectedRows = result.affectedRows ?? 0;
  if (affectedRows === 0) {
    throw new Error(`password_hash update affected 0 rows for user id ${userId}`);
  }
  return true;
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