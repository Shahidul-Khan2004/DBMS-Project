import pool from "../config/db.js";

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

/**
 * Databases initialized before incident status `reported` was removed from seed
 * (21_seed_reference_data.sql) may still have reference data and incidents on
 * `reported`. Re-home those incidents to `classified` via status history (trigger
 * syncs current_status_id) and deactivate the legacy status.
 */
export async function migrateLegacyReportedIncidentStatus() {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [reportedStatusRows] = await conn.execute(
      `
        SELECT id
        FROM incident_statuses
        WHERE status_code = 'reported'
        LIMIT 1
      `,
    );
    const reportedStatusId = reportedStatusRows[0]?.id ?? null;

    const [classifiedStatusRows] = await conn.execute(
      `
        SELECT id
        FROM incident_statuses
        WHERE status_code = 'classified' AND is_active = TRUE
        LIMIT 1
      `,
    );
    if (!classifiedStatusRows[0]) {
      await conn.commit();
      return;
    }
    const classifiedStatusId = classifiedStatusRows[0].id;

    const [incidentRows] = await conn.execute(
      `
        SELECT ei.id AS id
        FROM emergency_incidents ei
        INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
        WHERE ist.status_code = 'reported'
      `,
    );

    for (const incident of incidentRows) {
      await conn.execute(
        `
          INSERT INTO incident_status_history (
            incident_id,
            status_id,
            changed_by_user_id,
            note
          )
          VALUES (?, ?, NULL, ?)
        `,
        [
          incident.id,
          classifiedStatusId,
          "Migrated from legacy reported status to classified",
        ],
      );
    }

    if (reportedStatusId != null) {
      await conn.execute(
        `
          UPDATE incident_status_transitions
          SET is_active = FALSE
          WHERE from_status_id = ? OR to_status_id = ?
        `,
        [reportedStatusId, reportedStatusId],
      );
      await conn.execute(
        `
          UPDATE incident_statuses
          SET is_active = FALSE
          WHERE id = ?
        `,
        [reportedStatusId],
      );
    }

    await conn.execute(
      `
        UPDATE incident_statuses
        SET sort_order = 1
        WHERE status_code = 'classified'
      `,
    );

    await conn.commit();

    if (incidentRows.length > 0 || reportedStatusId != null) {
      console.log(
        `Applied schema migration: legacy reported incident status (${incidentRows.length} incident(s) reclassified)`,
      );
    }
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}
