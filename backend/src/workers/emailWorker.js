/**
 * workers/emailWorker.js
 * =======================
 * Starts the email polling worker as a setInterval loop.
 *
 * Called once from app.js during server startup (inside startServer()).
 * Runs for the lifetime of the Node.js process.
 *
 * Poll interval is controlled by MAIL_POLL_INTERVAL_MS in .env.
 * Default: 10000ms (10 seconds) — fine for development.
 * Recommended production value: 30000ms (30 seconds).
 *
 * The first cycle runs immediately on startup (runEmailWorkerCycle() called
 * directly before setInterval) so you don't have to wait one full interval
 * to see the first emails go out after a server restart.
 */

import { runEmailWorkerCycle } from "../services/emailWorkerService.js";

/**
 * Starts the email worker interval.
 * Safe to call multiple times — but should only be called once from app.js.
 */
export function startEmailWorker() {
  const intervalMs = Number(process.env.MAIL_POLL_INTERVAL_MS) || 10_000;

  console.log(`[emailWorker] Starting — polling every ${intervalMs / 1000}s`);

  // Run immediately on startup so any emails queued before the last restart
  // are picked up right away rather than waiting a full interval.
  runEmailWorkerCycle();

  // Then poll on a fixed interval for the lifetime of the process.
  setInterval(runEmailWorkerCycle, intervalMs);
}