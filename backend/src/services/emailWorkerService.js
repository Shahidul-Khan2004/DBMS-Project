/**
 * services/emailWorkerService.js
 * ================================
 * Polls email_outbox for pending rows and delivers them via the mailer.
 *
 * Flow per outbox row:
 *   1. Mark row as 'sending'              (prevents double-processing)
 *   2. Count prior attempts               (decides retry vs give up)
 *   3. Call sendEmail()                   (SMTP via mailer.js)
 *   4a. On success → markEmailSent()      (status = 'sent', logs attempt)
 *   4b. On failure, attempts < MAX_RETRIES → resetEmailForRetry() (back to 'pending' + backoff)
 *   4c. On failure, attempts >= MAX_RETRIES → markEmailFailed()   (status = 'failed', logs attempt)
 *
 * MAX_RETRIES = 3 — an email that fails 3 times is marked 'failed' permanently.
 * The email_delivery_attempts table has a full audit trail of every attempt.
 *
 * This service has no HTTP surface — it is started once by emailWorker.js
 * and runs for the lifetime of the Node.js process.
 */

import { sendEmail } from "../integrations/mailer.js";
import {
  fetchPendingEmails,
  markEmailSending,
  markEmailSent,
  markEmailFailed,
  resetEmailForRetry,
  countDeliveryAttempts,
} from "../repositories/emailOutboxRepo.js";

const MAX_RETRIES = 3;
const BATCH_SIZE  = 10; // rows processed per poll cycle

/**
 * Processes a single email_outbox row.
 *
 * Marked as a named function so stack traces are readable in logs.
 *
 * @param {object} outboxRow - Row from fetchPendingEmails()
 * @returns {Promise<void>}
 */
async function processOutboxRow(outboxRow) {
  const { id, to_email, subject, body } = outboxRow;

  // Step 1 — lock the row so no other worker cycle picks it up
  await markEmailSending(id);

  // Step 2 — how many times have we already tried this email?
  const priorAttempts = await countDeliveryAttempts(id);
  const attemptNumber = priorAttempts + 1;

  try {
    // Step 3 — send via SMTP
    const info = await sendEmail({ to: to_email, subject, text: body });

    // Step 4a — success
    const providerResponse = JSON.stringify({ messageId: info.messageId });
    await markEmailSent(id, attemptNumber, providerResponse);

    console.log(`[emailWorker] Sent email #${id} to ${to_email} (attempt ${attemptNumber})`);
  } catch (err) {
    const errorMessage = err?.message ?? String(err);
    console.error(`[emailWorker] Failed to send email #${id} to ${to_email} (attempt ${attemptNumber}):`, errorMessage);

    if (attemptNumber >= MAX_RETRIES) {
      // Step 4c — give up permanently
      await markEmailFailed(id, attemptNumber, errorMessage);
      console.error(`[emailWorker] Email #${id} permanently failed after ${MAX_RETRIES} attempts`);
    } else {
      // Step 4b — retry later with backoff
      await resetEmailForRetry(id, attemptNumber, errorMessage);
      console.log(`[emailWorker] Email #${id} queued for retry (attempt ${attemptNumber} of ${MAX_RETRIES})`);
    }
  }
}

/**
 * Runs one poll cycle — fetches up to BATCH_SIZE pending emails and processes them.
 *
 * Errors on individual rows are caught inside processOutboxRow() so one bad
 * email never stops the rest of the batch from being processed.
 *
 * Unexpected errors at the fetch level are caught here and logged — the worker
 * interval keeps running regardless.
 *
 * @returns {Promise<void>}
 */
export async function runEmailWorkerCycle() {
  try {
    const pendingEmails = await fetchPendingEmails(BATCH_SIZE);

    if (pendingEmails.length === 0) return; // nothing to do this cycle

    console.log(`[emailWorker] Processing ${pendingEmails.length} pending email(s)`);

    // Process rows sequentially — avoids hammering the SMTP server and keeps
    // logs readable. Switch to Promise.all() later if throughput becomes an issue.
    for (const row of pendingEmails) {
      await processOutboxRow(row);
    }
  } catch (err) {
    // Log but do not rethrow — the setInterval in emailWorker.js must keep running
    console.error("[emailWorker] Unexpected error during poll cycle:", err);
  }
}