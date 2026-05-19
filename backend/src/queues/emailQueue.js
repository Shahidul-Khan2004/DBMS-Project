

import { Queue } from "bullmq";
import { redisConnection } from "./redisConnection.js";

export const EMAIL_QUEUE_NAME = "email";

export const emailQueue = new Queue(EMAIL_QUEUE_NAME, {
  connection: redisConnection,
  defaultJobOptions: {
    attempts: Number(process.env.EMAIL_QUEUE_ATTEMPTS ?? 3),
    backoff: {
      type: "fixed",
      delay: Number(process.env.EMAIL_QUEUE_BACKOFF_MS ?? 60_000),
    },
    removeOnComplete: 100,
    removeOnFail: 200,
  },
});


export async function enqueueEmail(outboxId) {
  return emailQueue.add(
    "send-email",
    { outboxId },
    { jobId: `outbox-${outboxId}` },
  );
}