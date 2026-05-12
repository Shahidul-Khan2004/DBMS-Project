/**
 * notificationRepo.js
 * ===================
 * Data-access layer for all notification-related tables:
 *   - notification_templates   (looked up to resolve title / body / subject)
 *   - notifications            (one row per notification event)
 *   - notification_recipients  (one row per recipient × channel)
 *   - email_outbox             (one row per recipient when channel includes email)
 *
 * Conventions followed (matches every other repo in this project):
 *   - Simple reads  → query() helper from config/db.js (no transaction needed)
 *   - Writes        → pool.getConnection() + beginTransaction/commit/rollback/release
 *   - Private helpers that run inside a transaction receive `conn` as first argument
 *   - Raw DB rows are returned as-is; no camelCase mapping (service layer decides)
 *   - BackendError is thrown for expected domain failures
 */

import pool, { query } from "../config/db.js";
import BackendError from "../lib/BackendError.js";

// ─────────────────────────────────────────────────────────────
// Template resolution helpers
// ─────────────────────────────────────────────────────────────

/**
 * Looks up an active notification_templates row by template_code.
 * Returns null when no match — callers fall back to raw title/body.
 *
 * @param {object} conn
 * @param {string} templateCode  - e.g. 'intake_received__in_app'
 * @returns {Promise<{ id: number, subject_template: string|null, body_template: string }|null>}
 */
async function findTemplateByCode(conn, templateCode) {
  const [rows] = await conn.execute(
    `SELECT id, subject_template, body_template
     FROM notification_templates
     WHERE template_code = ? AND is_active = TRUE
     LIMIT 1`,
    [templateCode],
  );
  return rows[0] ?? null;
}

/**
 * Replaces {{placeholder}} tokens in a template string with values from a map.
 * Unknown tokens are left as-is so missing vars are visible, not silently blank.
 *
 * @param {string} template
 * @param {Record<string, string>} vars
 * @returns {string}
 */
function interpolate(template, vars) {
  return template.replace(/\{\{(\w+)\}\}/g, (match, key) => vars[key] ?? match);
}

// ─────────────────────────────────────────────────────────────
// Private in-transaction helpers
// ─────────────────────────────────────────────────────────────

/**
 * Inserts a single row into `notifications` inside an open transaction.
 *
 * Resolves the in_app template (templateCode + '__in_app') to populate:
 *   - template_id  (FK to notification_templates, no longer NULL)
 *   - title        (interpolated from subject_template or fallbackTitle)
 *   - body         (interpolated from body_template or fallbackBody)
 *
 * Falls back to fallbackTitle / fallbackBody when no active template found.
 *
 * @param {object} conn
 * @param {object} params
 * @param {string} params.notificationType
 * @param {string} params.templateCode       - Base code e.g. 'intake_received'
 * @param {Record<string,string>} params.templateVars
 * @param {string} params.fallbackTitle
 * @param {string} params.fallbackBody
 * @param {string|null} params.entityType
 * @param {number|null} params.entityId
 * @param {number|null} params.createdByUserId
 *
 * @returns {Promise<{ notificationId: number, resolvedTitle: string, resolvedBody: string }>}
 */
async function insertNotificationRow(conn, params) {
  const inAppCode = `${params.templateCode}__in_app`;
  const template  = await findTemplateByCode(conn, inAppCode);

  let templateId    = null;
  let resolvedTitle = params.fallbackTitle;
  let resolvedBody  = params.fallbackBody;

  if (template) {
    templateId    = template.id;
    resolvedTitle = template.subject_template
      ? interpolate(template.subject_template, params.templateVars)
      : params.fallbackTitle;
    resolvedBody  = interpolate(template.body_template, params.templateVars);
  }

  const [result] = await conn.execute(
    `
      INSERT INTO notifications (
        template_id,
        notification_type,
        title,
        body,
        entity_type,
        entity_id,
        created_by_user_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      templateId,
      params.notificationType,
      resolvedTitle,
      resolvedBody,
      params.entityType      ?? null,
      params.entityId        ?? null,
      params.createdByUserId ?? null,
    ],
  );

  return { notificationId: result.insertId, resolvedTitle, resolvedBody };
}

/**
 * Inserts one notification_recipients row per recipient inside an open transaction.
 *
 * @param {object}   conn
 * @param {number}   notificationId
 * @param {number[]} recipientUserIds
 * @param {string}   deliveryChannel  - 'in_app' or 'email'
 */
async function insertRecipientRows(conn, notificationId, recipientUserIds, deliveryChannel) {
  for (const userId of recipientUserIds) {
    await conn.execute(
      `
        INSERT INTO notification_recipients (
          notification_id,
          recipient_user_id,
          delivery_channel
        )
        VALUES (?, ?, ?)
      `,
      [notificationId, userId, deliveryChannel],
    );
  }
}

/**
 * Inserts one email_outbox row per recipient inside an open transaction.
 *
 * Resolves the email-specific template (templateCode + '__email') separately
 * from the in_app template so email bodies can be richer (multi-line, greeting, etc.).
 *
 * @param {object}   conn
 * @param {number}   notificationId
 * @param {number[]} recipientUserIds
 * @param {string}   templateCode      - Base code e.g. 'intake_received'
 * @param {Record<string,string>} templateVars
 * @param {string}   fallbackSubject   - Used when template not found (= in_app title)
 * @param {string}   fallbackBody      - Used when template not found (= in_app body)
 */
async function insertEmailOutboxRows(
  conn,
  notificationId,
  recipientUserIds,
  templateCode,
  templateVars,
  fallbackSubject,
  fallbackBody,
) {
  // Resolve the email-specific template once, shared across all recipients.
  const emailCode     = `${templateCode}__email`;
  const emailTemplate = await findTemplateByCode(conn, emailCode);

  let emailSubject = fallbackSubject;
  let emailBody    = fallbackBody;

  if (emailTemplate) {
    emailSubject = emailTemplate.subject_template
      ? interpolate(emailTemplate.subject_template, templateVars)
      : fallbackSubject;
    emailBody = interpolate(emailTemplate.body_template, templateVars);
  }

  for (const userId of recipientUserIds) {
    const [rows] = await conn.execute(
      `SELECT email FROM users WHERE id = ? LIMIT 1`,
      [userId],
    );

    // Skip silently — avoids aborting the whole notification for one bad recipient.
    if (!rows[0]) continue;

    await conn.execute(
      `
        INSERT INTO email_outbox (
          notification_id,
          recipient_user_id,
          to_email,
          subject,
          body,
          email_status
        )
        VALUES (?, ?, ?, ?, ?, 'pending')
      `,
      [notificationId, userId, rows[0].email, emailSubject, emailBody],
    );
  }
}

// ─────────────────────────────────────────────────────────────
// Exported write function
// ─────────────────────────────────────────────────────────────

/**
 * Creates a notification and all its delivery records in a single atomic transaction.
 *
 * Write order:
 *   1. notification_templates  — looked up (read) to resolve title / body / subject
 *   2. notifications           — one row; template_id populated when template found
 *   3. notification_recipients — one row per (recipientUserId × channel)
 *   4. email_outbox            — one row per recipient when channel includes email
 *
 * @param {object}   params
 * @param {string}   params.notificationType
 * @param {string}   params.templateCode        - Base code WITHOUT channel suffix
 * @param {Record<string,string>} params.templateVars
 * @param {string}   params.fallbackTitle
 * @param {string}   params.fallbackBody
 * @param {string|null}  params.entityType
 * @param {number|null}  params.entityId
 * @param {number[]} params.recipientUserIds
 * @param {number|null}  params.createdByUserId
 * @param {'in_app'|'email'|'both'} params.deliveryChannel
 *
 * @returns {Promise<{ notificationId: number, recipientCount: number }>}
 * @throws {BackendError} If recipientUserIds is empty
 */
export async function insertNotificationWithRecipients(params) {
  if (!params.recipientUserIds || params.recipientUserIds.length === 0) {
    throw new BackendError(
      422,
      "NOTIFICATION_REQUIRES_RECIPIENTS",
      "At least one recipient is required to create a notification",
    );
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Step 1 — resolve in_app template + insert notifications row
    const { notificationId, resolvedTitle, resolvedBody } = await insertNotificationRow(conn, {
      notificationType:  params.notificationType,
      templateCode:      params.templateCode,
      templateVars:      params.templateVars  ?? {},
      fallbackTitle:     params.fallbackTitle,
      fallbackBody:      params.fallbackBody,
      entityType:        params.entityType    ?? null,
      entityId:          params.entityId      ?? null,
      createdByUserId:   params.createdByUserId ?? null,
    });

    // Step 2 — insert notification_recipients rows
    const channels = params.deliveryChannel === "both"
      ? ["in_app", "email"]
      : [params.deliveryChannel];

    for (const channel of channels) {
      await insertRecipientRows(conn, notificationId, params.recipientUserIds, channel);
    }

    // Step 3 — queue email_outbox rows (email template resolved inside)
    if (params.deliveryChannel === "email" || params.deliveryChannel === "both") {
      await insertEmailOutboxRows(
        conn,
        notificationId,
        params.recipientUserIds,
        params.templateCode,
        params.templateVars ?? {},
        resolvedTitle,   // fallback subject  = in_app title
        resolvedBody,    // fallback body     = in_app body
      );
    }

    await conn.commit();
    return {
      notificationId,
      recipientCount: params.recipientUserIds.length,
    };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

// ─────────────────────────────────────────────────────────────
// Exported read functions
// ─────────────────────────────────────────────────────────────

/**
 * Lists in_app notifications for a user (newest first).
 * Email rows are excluded — those are for the worker only.
 *
 * @param {number}  recipientUserId
 * @param {object}  [options]
 * @param {boolean} [options.unreadOnly=false]
 * @param {number}  [options.limit=20]
 * @param {number}  [options.offset=0]
 * @returns {Promise<object[]>}
 */
export async function listNotificationsByRecipientUserId(recipientUserId, options = {}) {
  const unreadOnly   = options.unreadOnly ?? false;
  const limit        = options.limit      ?? 20;
  const offset       = options.offset     ?? 0;
  const unreadClause = unreadOnly ? "AND nr.read_at IS NULL" : "";

  const result = await query(
    `
      SELECT
        nr.id           AS notification_recipient_id,
        n.id            AS notification_id,
        n.notification_type,
        n.title,
        n.body,
        n.entity_type,
        n.entity_id,
        nr.delivery_channel,
        nr.read_at,
        nr.created_at
      FROM notification_recipients nr
      INNER JOIN notifications n ON n.id = nr.notification_id
      WHERE nr.recipient_user_id = ?
        AND nr.delivery_channel = 'in_app'
      ${unreadClause}
      ORDER BY nr.created_at DESC
      LIMIT ? OFFSET ?
    `,
    [recipientUserId, limit, offset],
  );

  return result.rows;
}

/**
 * Returns the count of unread in_app notifications for a user.
 *
 * @param {number} recipientUserId
 * @returns {Promise<number>}
 */
export async function countUnreadByRecipientUserId(recipientUserId) {
  const result = await query(
    `
      SELECT COUNT(*) AS unread_count
      FROM notification_recipients
      WHERE recipient_user_id = ?
        AND delivery_channel = 'in_app'
        AND read_at IS NULL
    `,
    [recipientUserId],
  );
  return Number(result.rows[0]?.unread_count ?? 0);
}

/**
 * Marks a single notification_recipients row as read.
 * Ownership enforced via AND recipient_user_id = ?.
 *
 * @param {number} notificationRecipientId
 * @param {number} recipientUserId
 * @returns {Promise<void>}
 * @throws {BackendError} 404 if row not found or belongs to another user
 */
export async function markNotificationRecipientRead(notificationRecipientId, recipientUserId) {
  const result = await query(
    `
      UPDATE notification_recipients
      SET read_at = COALESCE(read_at, CURRENT_TIMESTAMP)
      WHERE id = ?
        AND recipient_user_id = ?
    `,
    [notificationRecipientId, recipientUserId],
  );

  const affectedRows = result.rows.affectedRows ?? 0;
  if (affectedRows === 0) {
    throw new BackendError(404, "NOTIFICATION_NOT_FOUND", "Notification not found");
  }
}