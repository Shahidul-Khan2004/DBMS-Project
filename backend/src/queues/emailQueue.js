import { Queue } from "bullmq";
import { redisConnection } from "./redisConnection.js";

export const EMAIL_QUEUE_NAME = "email";

let emailQueue = null;

export function isEmailQueueEnabled() {
  return process.env.EMAIL_QUEUE_ENABLED === "true";
}

function getEmailQueue() {
  if (!isEmailQueueEnabled()) {
    return null;
  }
  if (!emailQueue) {
    emailQueue = new Queue(EMAIL_QUEUE_NAME, {
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
  }
  return emailQueue;
}

export async function enqueueEmail(outboxId) {
  const queue = getEmailQueue();
  if (!queue) {
    return null;
  }
  return queue.add(
    "send-email",
    { outboxId },
    { jobId: `outbox-${outboxId}` },
  );
}
