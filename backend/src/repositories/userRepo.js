import { query } from "../config/db.js";

export async function findUserByEmail(email) {
  const result = await query(
    `
      SELECT
        id,
        public_uuid,
        email,
        full_name,
        password_hash,
        phone_number,
        is_active,
        created_at,
        updated_at
      FROM users
      WHERE email = ?
    `,
    [email]
  );

  return result.rows[0] || null;
}

export async function findUserByPublicUuid(publicUuid) {
  const result = await query(
    `
      SELECT
        id,
        public_uuid,
        email,
        full_name,
        password_hash,
        phone_number,
        is_active,
        created_at,
        updated_at
      FROM users
      WHERE public_uuid = ?
    `,
    [publicUuid]
  );

  return result.rows[0] || null;
}

export async function createUser({ publicUuid, email, fullName, phoneNumber, passwordHash }) {
  await query(
    `
      INSERT INTO users (public_uuid, email, full_name, password_hash, phone_number)
      VALUES (?, ?, ?, ?, ?)
    `,
    [publicUuid, email, fullName, passwordHash, phoneNumber ?? null]
  );
}
