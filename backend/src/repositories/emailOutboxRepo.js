

import pool, { query } from "../config/db.js";


export async function findEmailOutboxById(outboxId) {
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
      WHERE id = ?
    `,
    [outboxId],
  );
  return result.rows[0] ?? null;
}


export async function findPendingEmailOutboxIds(limit = 200) {
  const result = await query(
    `
      SELECT id
      FROM email_outbox
      WHERE email_status = 'pending'
        AND (available_to_send_at IS NULL OR available_to_send_at <= NOW())
      ORDER BY created_at ASC
      LIMIT ?
    `,
    [limit],
  );
  return result.rows.map((r) => r.id);
}



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


export async function markEmailSending(outboxId) {
  const result = await query(
    `
      UPDATE email_outbox
      SET email_status = 'sending',
          updated_at   = CURRENT_TIMESTAMP
      WHERE id = ?
        AND email_status = 'pending'
    `,
    [outboxId],
  );
  return result.rows.affectedRows === 1;
}


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