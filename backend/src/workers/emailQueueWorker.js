/**
 * workers/emailQueueWorker.js
 * ============================
 * BullMQ Worker for the email delivery queue.
 *
 * startEmailQueueWorker() is called once from app.js on server startup.
 * It does two things:
 *   1. Runs recoverPendingEmails() to enqueue any pending rows that were
 *      never picked up (e.g. server crashed before enqueue, or enqueue failed).
 *   2. Starts a BullMQ Worker that processes jobs concurrently.
 *
 * Environment variables:
 *   EMAIL_QUEUE_ENABLED      - Set to "true" to activate (default: off)
 *   EMAIL_QUEUE_CONCURRENCY  - Jobs processed in parallel (default: 2)
 */

import { Worker } from "bullmq";
import { EMAIL_QUEUE_NAME, enqueueEmail } from "../queues/emailQueue.js";
import { redisConnection } from "../queues/redisConnection.js";
import { processEmailOutboxJob } from "../services/emailWorkerService.js";
import { findPendingEmailOutboxIds } from "../repositories/emailOutboxRepo.js";

// Guard against calling startEmailQueueWorker() more than once in the same process.
let workerStarted = false;


/**
 * Re-enqueues all pending email_outbox rows on startup.
 *
 * Covers the gap where:
 *   - The server crashed after the DB insert but before enqueueEmail() ran, or
 *   - enqueueEmail() threw and the error was swallowed by notificationService.
 *
 * BullMQ's deterministic jobId (`outbox-${outboxId}`) means rows that are
 * already queued will be silently de-duped, so this is safe to run every time.
 *
 * @returns {Promise<void>}
 */
async function recoverPendingEmails() {
  console.log("[emailQueueWorker] Running startup recovery sweep...");

  let ids;
  try {
    ids = await findPendingEmailOutboxIds(200);
  } catch (err) {
    console.error("[emailQueueWorker] Recovery sweep failed to fetch pending IDs:", err?.message ?? err);
    return;
  }

  if (ids.length === 0) {
    console.log("[emailQueueWorker] Recovery sweep: no pending rows found.");
    return;
  }

  console.log(`[emailQueueWorker] Recovery sweep: found ${ids.length} pending row(s) — enqueuing...`);

  for (const outboxId of ids) {
    try {
      await enqueueEmail(outboxId);
    } catch (err) {
      // Log per-row but continue — one bad enqueue should not stop the rest.
      console.error(
        `[emailQueueWorker] Recovery sweep: failed to enqueue outboxId=${outboxId}:`,
        err?.message ?? err,
      );
    }
  }

  console.log("[emailQueueWorker] Recovery sweep complete.");
}


/**
 * Starts the BullMQ email worker and the startup recovery sweep.
 * Safe to import but calling it twice in the same process is a no-op (guarded).
 *
 * @returns {void}
 */
export function startEmailQueueWorker() {
  if (process.env.EMAIL_QUEUE_ENABLED !== "true") {
    console.log("[emailQueueWorker] EMAIL_QUEUE_ENABLED is not 'true' — worker not started.");
    return;
  }

  if (workerStarted) {
    console.warn("[emailQueueWorker] startEmailQueueWorker() called more than once — ignoring.");
    return;
  }
  workerStarted = true;

  const concurrency = Number(process.env.EMAIL_QUEUE_CONCURRENCY ?? 2);

  const worker = new Worker(
    EMAIL_QUEUE_NAME,
    async (job) => {
      console.log(`[emailQueueWorker] Processing job ${job.id}, outboxId=${job.data.outboxId}`);
      const { outboxId } = job.data;

      // BullMQ uses 0-based attemptsMade; we want 1-based for logs and DB.
      const attemptNumber = job.attemptsMade + 1;
      const maxAttempts   = job.opts.attempts ?? 1;

      await processEmailOutboxJob(outboxId, { attemptNumber, maxAttempts });
    },
    {
      connection:  redisConnection,
      concurrency,
    },
  );

  worker.on("completed", (job) => {
    console.log(
      `[emailQueueWorker] Job ${job.id} completed (outboxId=${job.data.outboxId})`,
    );
  });

  worker.on("failed", (job, err) => {
    console.error(
      `[emailQueueWorker] Job ${job?.id} failed (outboxId=${job?.data?.outboxId}): ${err?.message ?? err}`,
    );
  });

  worker.on("error", (err) => {
    console.error("[emailQueueWorker] Worker error:", err?.message ?? err);
  });

  console.log(
    `[emailQueueWorker] Started — concurrency=${concurrency}, queue='${EMAIL_QUEUE_NAME}'`,
  );

  // Run recovery sweep after worker is listening so jobs are immediately picked up.
  recoverPendingEmails().catch((err) => {
    console.error("[emailQueueWorker] Unexpected error during recovery sweep:", err);
  });
}