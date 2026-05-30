import pool from "../config/db.js";

/**
 * Adds user_profiles.secondary_phone_number on databases created before this migration.
 * Fresh installs already have the column from docker-init/06_geography_and_service_zones.sql.
 */
export async function ensureUserProfilesSecondaryPhoneNumber() {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS column_count
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'user_profiles'
        AND COLUMN_NAME = 'secondary_phone_number'
    `,
  );

  if (Number(rows[0]?.column_count) > 0) {
    return;
  }

  await pool.execute(
    `ALTER TABLE user_profiles ADD COLUMN secondary_phone_number VARCHAR(30) NULL AFTER phone_number`,
  );

  console.log("Applied schema migration: user_profiles.secondary_phone_number");
}

/**
 * Adds agency_memberships.public_uuid on databases created before docker-init/27.
 * Fresh installs already have the column from 09_agencies_and_units.sql.
 */
export async function ensureAgencyMembershipsPublicUuid() {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS column_count
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'agency_memberships'
        AND COLUMN_NAME = 'public_uuid'
    `,
  );

  if (Number(rows[0]?.column_count) > 0) {
    return;
  }

  await pool.execute(
    `ALTER TABLE agency_memberships ADD COLUMN public_uuid CHAR(36) NULL AFTER id`,
  );
  await pool.execute(
    `UPDATE agency_memberships SET public_uuid = UUID() WHERE public_uuid IS NULL`,
  );
  await pool.execute(
    `
      ALTER TABLE agency_memberships
      MODIFY public_uuid CHAR(36) NOT NULL,
      ADD UNIQUE KEY uq_agency_memberships_public_uuid (public_uuid)
    `,
  );

  console.log("Applied schema migration: agency_memberships.public_uuid");
}