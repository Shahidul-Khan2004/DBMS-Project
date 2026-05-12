/**
 * repositories/emailOutboxRepo.js
 * ================================
 * DB queries used exclusively by the email worker.
 *
 * Covers:
 *   - email_outbox      (read pending, mark sending/sent/failed)
 *   - email_delivery_attempts (insert one row per send attempt)
 *
 * Conventions followed (matches every other repo in this project):
 *   - Simple reads  → query() helper from config/db.js
 *   - Writes        → pool.getConnection() + transaction where atomicity matters
 *   - Raw DB rows returned as-is
 */

import pool, { query } from "../config/db.js";

/**
 * Fetches a batch of pending email_outbox rows that are ready to send.
 *
 * "Ready" means:
 *   - email_status = 'pending'
 *   - available_to_send_at <= NOW()  (allows scheduled/delayed sends)
 *
 * Ordered oldest-first so emails are sent in the order they were queued.
 * Batch size is capped at `limit` to avoid processing too many at once.
 *
 * @param {number} [limit=10] - Max rows to fetch per poll cycle
 * @returns {Promise<Array<{
 *   id:                  number,
 *   notification_id:     number|null,
 *   recipient_user_id:   number|null,
 *   to_email:            string,
 *   subject:             string,
 *   body:                string,
 *   email_status:        string,
 *   available_to_send_at: Date,
 *   created_at:          Date
 * }>>}
 */
export async function fetchPendingEmails(limit = 10) {
  const result = await query(
    `
      SELECT
        id,
        notification_id,
        recipient_user_id,
        to_email,
        subject,
        body,
        email_status,
        available_to_send_at,
        created_at
      FROM email_outbox
      WHERE email_status = 'pending'
        AND available_to_send_at <= NOW()
      ORDER BY available_to_send_at ASC
      LIMIT ?
    `,
    [limit],
  );
  return result.rows;
}

/**
 * Marks an email_outbox row as 'sending' before attempting delivery.
 *
 * This prevents a second worker instance (or the next poll cycle) from
 * picking up the same row while it is being processed.
 *
 * @param {number} outboxId - email_outbox.id
 * @returns {Promise<void>}
 */
export async function markEmailSending(outboxId) {
  await query(
    `
      UPDATE email_outbox
      SET email_status = 'sending',
          updated_at   = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
    [outboxId],
  );
}

/**
 * Marks an email_outbox row as 'sent' and records the delivery timestamp.
 * Also inserts a success row into email_delivery_attempts.
 *
 * Both writes happen in a single transaction so the audit trail is always
 * consistent with the outbox status.
 *
 * @param {number} outboxId       - email_outbox.id
 * @param {number} attemptNumber  - Which attempt this was (1, 2, 3 …)
 * @param {string} providerResponse - Stringified provider info (e.g. messageId)
 * @returns {Promise<void>}
 */
export async function markEmailSent(outboxId, attemptNumber, providerResponse) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    await conn.execute(
      `
        UPDATE email_outbox
        SET email_status = 'sent',
            sent_at      = CURRENT_TIMESTAMP,
            updated_at   = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [outboxId],
    );

    await conn.execute(
      `
        INSERT INTO email_delivery_attempts (
          email_outbox_id,
          attempt_number,
          attempt_status,
          provider_response
        )
        VALUES (?, ?, 'success', ?)
      `,
      [outboxId, attemptNumber, providerResponse],
    );

    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

/**
 * Marks an email_outbox row as 'failed' and records the error.
 * Also inserts a failed row into email_delivery_attempts.
 *
 * Called after the final retry attempt is exhausted.
 *
 * @param {number} outboxId       - email_outbox.id
 * @param {number} attemptNumber  - Which attempt this was
 * @param {string} errorMessage   - The error message from the SMTP provider
 * @returns {Promise<void>}
 */
export async function markEmailFailed(outboxId, attemptNumber, errorMessage) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    await conn.execute(
      `
        UPDATE email_outbox
        SET email_status = 'failed',
            updated_at   = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [outboxId],
    );

    await conn.execute(
      `
        INSERT INTO email_delivery_attempts (
          email_outbox_id,
          attempt_number,
          attempt_status,
          error_message
        )
        VALUES (?, ?, 'failed', ?)
      `,
      [outboxId, attemptNumber, errorMessage],
    );

    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

/**
 * Resets a 'sending' row back to 'pending' so it can be retried.
 *
 * Called when a send attempt fails but we haven't hit the max retry limit yet.
 * Sets available_to_send_at 60 seconds into the future to add a small backoff
 * between retries.
 *
 * Also inserts a failed attempt row for the audit trail.
 *
 * @param {number} outboxId       - email_outbox.id
 * @param {number} attemptNumber  - Which attempt just failed
 * @param {string} errorMessage   - Error from the SMTP provider
 * @returns {Promise<void>}
 */
export async function resetEmailForRetry(outboxId, attemptNumber, errorMessage) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Push available_to_send_at 60 seconds forward — simple fixed backoff.
    await conn.execute(
      `
        UPDATE email_outbox
        SET email_status         = 'pending',
            available_to_send_at = DATE_ADD(NOW(), INTERVAL 60 SECOND),
            updated_at           = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [outboxId],
    );

    await conn.execute(
      `
        INSERT INTO email_delivery_attempts (
          email_outbox_id,
          attempt_number,
          attempt_status,
          error_message
        )
        VALUES (?, ?, 'failed', ?)
      `,
      [outboxId, attemptNumber, errorMessage],
    );

    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

/**
 * Counts how many delivery attempts have already been made for an outbox row.
 *
 * Used by the worker to decide whether to retry or give up.
 *
 * @param {number} outboxId - email_outbox.id
 * @returns {Promise<number>}
 */
export async function countDeliveryAttempts(outboxId) {
  const result = await query(
    `
      SELECT COUNT(*) AS attempt_count
      FROM email_delivery_attempts
      WHERE email_outbox_id = ?
    `,
    [outboxId],
  );
  return Number(result.rows[0]?.attempt_count ?? 0);
}