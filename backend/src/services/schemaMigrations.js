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
 * Adds soft-unlink support to incident_report_links.
 * Allows unlinking intake reports from incidents while preserving audit trail.
 * Supports historical unlinked rows while enforcing single-active-link uniqueness.
 */
export async function ensureIncidentReportLinksSoftUnlink() {
  // Check if migration already applied by looking for unlinked_at column
  const [columns] = await pool.execute(
    `
      SELECT COUNT(*) AS column_count
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'incident_report_links'
        AND COLUMN_NAME = 'unlinked_at'
    `,
  );

  if (Number(columns[0]?.column_count) > 0) {
    return;
  }

  // Add soft-unlink columns
  await pool.execute(
    `
      ALTER TABLE incident_report_links
      ADD COLUMN unlinked_at TIMESTAMP NULL AFTER note,
      ADD COLUMN unlinked_by_user_id BIGINT UNSIGNED NULL AFTER unlinked_at,
      ADD COLUMN unlink_reason VARCHAR(500) NULL AFTER unlinked_by_user_id
    `,
  );

  // Add foreign key for unlinked_by_user_id
  try {
    await pool.execute(
      `
        ALTER TABLE incident_report_links
        ADD CONSTRAINT fk_incident_report_links_unlinked_by_user 
        FOREIGN KEY (unlinked_by_user_id) REFERENCES users(id) 
        ON DELETE RESTRICT ON UPDATE RESTRICT
      `,
    );
  } catch (err) {
    // Foreign key may already exist from fresh install
    if (!err.message.includes("Duplicate key name")) {
      throw err;
    }
  }

  // Add index for unlinked_by_user_id
  try {
    await pool.execute(
      `
        ALTER TABLE incident_report_links
        ADD INDEX idx_incident_report_links_unlinked_by_user (unlinked_by_user_id)
      `,
    );
  } catch (err) {
    // Index may already exist from fresh install
    if (!err.message.includes("Duplicate key name")) {
      throw err;
    }
  }

  // Add generated columns for active-link uniqueness
  // These are stored (persisted to disk) so they can be indexed
  try {
    await pool.execute(
      `
        ALTER TABLE incident_report_links
        ADD COLUMN active_incident_report_incident_id BIGINT UNSIGNED 
          GENERATED ALWAYS AS (CASE WHEN unlinked_at IS NULL THEN incident_id ELSE NULL END) STORED,
        ADD COLUMN active_incident_report_intake_id BIGINT UNSIGNED 
          GENERATED ALWAYS AS (CASE WHEN unlinked_at IS NULL THEN intake_report_id ELSE NULL END) STORED,
        ADD COLUMN active_intake_report_id BIGINT UNSIGNED 
          GENERATED ALWAYS AS (CASE WHEN unlinked_at IS NULL THEN intake_report_id ELSE NULL END) STORED
      `,
    );
  } catch (err) {
    // Generated columns may already exist from fresh install
    if (!err.message.includes("Duplicate column name")) {
      throw err;
    }
  }

  // Drop old unique indexes that prevent relinking.
  // MySQL treats unique constraints as indexes; DROP CONSTRAINT is only valid for
  // CHECK constraints in MySQL 8.0+. Use guarded DROP INDEX instead so this is
  // safe whether the index was created via ADD CONSTRAINT … UNIQUE KEY or
  // ADD UNIQUE INDEX, and whether it already existed or not.
  for (const indexName of [
    "uq_incident_report_links_incident_report",
    "uq_incident_report_links_one_incident_per_report",
  ]) {
    const [idxRows] = await pool.execute(
      `SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME   = 'incident_report_links'
         AND INDEX_NAME   = ?
       LIMIT 1`,
      [indexName],
    );
    if (idxRows.length > 0) {
      await pool.execute(
        `ALTER TABLE incident_report_links DROP INDEX \`${indexName}\``,
      );
    }
  }

  // Add new unique constraints for active links only
  try {
    await pool.execute(
      `
        ALTER TABLE incident_report_links
        ADD CONSTRAINT uq_incident_report_links_active_incident_report 
        UNIQUE KEY (active_incident_report_incident_id, active_incident_report_intake_id)
      `,
    );
  } catch (err) {
    // Unique key may already exist from fresh install
    if (!err.message.includes("Duplicate key name")) {
      throw err;
    }
  }

  try {
    await pool.execute(
      `
        ALTER TABLE incident_report_links
        ADD CONSTRAINT uq_incident_report_links_active_one_incident_per_report 
        UNIQUE KEY (active_intake_report_id)
      `,
    );
  } catch (err) {
    // Unique key may already exist from fresh install
    if (!err.message.includes("Duplicate key name")) {
      throw err;
    }
  }

  // Add CHECK constraint for unlink_reason requirement
  try {
    await pool.execute(
      `
        ALTER TABLE incident_report_links
        ADD CONSTRAINT chk_incident_report_links_unlink_reason_when_unlinked 
        CHECK (unlinked_at IS NULL OR (unlink_reason IS NOT NULL AND CHAR_LENGTH(TRIM(unlink_reason)) > 0))
      `,
    );
  } catch (err) {
    // Constraint may already exist from fresh install
    if (!err.message.includes("Constraint chk_incident_report_links_unlink_reason_when_unlinked")) {
      throw err;
    }
  }

  console.log("Applied schema migration: incident_report_links soft-unlink support");
}

/**
 * Updates intake status workflow to allow unlinking reports from incidents.
 * Sets linked_to_incident to non-terminal and adds transition back to under_review.
 */
export async function ensureIntakeStatusUnlinkTransition() {
  // Step 1: Update linked_to_incident to be non-terminal (idempotent)
  const [statusRows] = await pool.execute(
    `
      SELECT id, is_terminal
      FROM intake_statuses
      WHERE status_code = 'linked_to_incident'
    `,
  );

  if (statusRows.length === 0) {
    throw new Error("Status code 'linked_to_incident' not found in intake_statuses");
  }

  const linkedToIncidentStatus = statusRows[0];

  if (linkedToIncidentStatus.is_terminal) {
    await pool.execute(
      `
        UPDATE intake_statuses
        SET is_terminal = FALSE
        WHERE status_code = 'linked_to_incident'
      `,
    );
  }

  // Step 2: Add transition linked_to_incident -> under_review (idempotent)
  // First, look up both status ids by code
  const [statuses] = await pool.execute(
    `
      SELECT id, status_code
      FROM intake_statuses
      WHERE status_code IN ('linked_to_incident', 'under_review')
    `,
  );

  if (statuses.length !== 2) {
    throw new Error(
      "Could not find required intake statuses: linked_to_incident and under_review",
    );
  }

  const linkedToIncidentId = statuses.find(
    (s) => s.status_code === "linked_to_incident",
  )?.id;
  const underReviewId = statuses.find((s) => s.status_code === "under_review")?.id;

  if (!linkedToIncidentId || !underReviewId) {
    throw new Error(
      "Could not determine status IDs for linked_to_incident or under_review",
    );
  }

  // Check if transition already exists
  const [existingTransition] = await pool.execute(
    `
      SELECT id
      FROM intake_status_transitions
      WHERE from_status_id = ? AND to_status_id = ?
    `,
    [linkedToIncidentId, underReviewId],
  );

  if (existingTransition.length === 0) {
    // Transition doesn't exist yet, insert it
    await pool.execute(
      `
        INSERT INTO intake_status_transitions (from_status_id, to_status_id, is_active, requires_note)
        VALUES (?, ?, TRUE, FALSE)
      `,
      [linkedToIncidentId, underReviewId],
    );
  }

  console.log("Applied schema migration: intake status unlink transition");
}