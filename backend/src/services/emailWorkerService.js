/**
 * services/emailWorkerService.js
 * ================================
 * Email delivery logic for the BullMQ worker.
 *
 * processEmailOutboxJob() is called once per BullMQ job.
 * It handles the full lifecycle of one email_outbox row:
 *   1. Load the row
 *   2. Guard against already-sent or non-pending rows
 *   3. Claim it (pending → sending) with an atomic UPDATE
 *   4. Send via SMTP
 *   5a. Success → markEmailSent()
 *   5b. Failure, not final attempt → resetEmailForRetry() + throw (BullMQ retries)
 *   5c. Failure, final attempt     → markEmailFailed()    + throw
 *
 * Critical retry rule:
 *   email_status is ONLY set to 'failed' on the final attempt.
 *   On earlier failures the row is reset to 'pending' so the safe-claim
 *   UPDATE (WHERE email_status = 'pending') can pick it up again on retry.
 *
 * runEmailWorkerCycle() is kept as a no-op export for backward compatibility
 * in case any other file still imports it.
 */

import { sendEmail } from "../integrations/mailer.js";
import {
  findEmailOutboxById,
  markEmailSending,
  markEmailSent,
  markEmailFailed,
  resetEmailForRetry,
} from "../repositories/emailOutboxRepo.js";


/**
 * Processes one email_outbox row identified by outboxId.
 *
 * @param {number} outboxId
 * @param {object} [options]
 * @param {number} [options.attemptNumber=1]  - Current attempt (1-based)
 * @param {number} [options.maxAttempts=1]    - Total attempts BullMQ will make
 * @returns {Promise<void>}
 */
export async function processEmailOutboxJob(outboxId, options = {}) {
  const { attemptNumber = 1, maxAttempts = 1 } = options;

  // Step 1 — load the row
  const row = await findEmailOutboxById(outboxId);

  if (!row) {
    console.warn(`[emailWorkerService] outboxId=${outboxId} not found — skipping`);
    return;
  }

  // Step 2 — guard: skip rows that are already done or in a non-retryable state
  if (row.email_status === "sent") {
    console.log(`[emailWorkerService] outboxId=${outboxId} already sent — skipping`);
    return;
  }

  if (row.email_status !== "pending") {
    // Could be 'sending' (another worker claimed it) or 'failed'
    console.warn(
      `[emailWorkerService] outboxId=${outboxId} has status='${row.email_status}' — skipping`,
    );
    return;
  }

  // Step 3 — atomic claim: pending → sending
  const claimed = await markEmailSending(outboxId);
  if (!claimed) {
    // Another worker beat us to it — back off silently
    console.warn(
      `[emailWorkerService] outboxId=${outboxId} claim failed (already taken) — skipping`,
    );
    return;
  }

  // Step 4 — send
  try {
    const info = await sendEmail({
      to:      row.to_email,
      subject: row.subject,
      text:    row.body,
    });

    // Step 5a — success
    const providerResponse = JSON.stringify({ messageId: info.messageId });
    await markEmailSent(outboxId, attemptNumber, providerResponse);

    console.log(
      `[emailWorkerService] Sent outboxId=${outboxId} to ${row.to_email} (attempt ${attemptNumber}/${maxAttempts})`,
    );
  } catch (err) {
    const errorMessage = err?.message ?? String(err);
    console.error(
      `[emailWorkerService] Failed outboxId=${outboxId} to ${row.to_email} ` +
      `(attempt ${attemptNumber}/${maxAttempts}): ${errorMessage}`,
    );

    if (attemptNumber >= maxAttempts) {
      // Step 5c — final attempt exhausted: mark permanently failed
      await markEmailFailed(outboxId, attemptNumber, errorMessage);
      console.error(
        `[emailWorkerService] outboxId=${outboxId} permanently failed after ${maxAttempts} attempt(s)`,
      );
    } else {
      // Step 5b — more retries remain: reset to pending so next attempt can claim it
      await resetEmailForRetry(outboxId, attemptNumber, errorMessage);
      console.log(
        `[emailWorkerService] outboxId=${outboxId} reset to pending for retry ` +
        `(attempt ${attemptNumber} of ${maxAttempts})`,
      );
    }

    // Throw so BullMQ knows the job failed and schedules the next attempt.
    throw err;
  }
}


/**
 * No-op kept for backward compatibility.
 * The old polling worker called this on an interval; the BullMQ worker does not.
 * Remove once all import sites are confirmed gone.
 */
export async function runEmailWorkerCycle() {
  console.warn(
    "[emailWorkerService] runEmailWorkerCycle() is a no-op — " +
    "the BullMQ worker is now handling email delivery.",
  );
}