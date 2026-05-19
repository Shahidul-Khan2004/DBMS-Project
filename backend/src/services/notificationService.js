/**
 * notificationService.js
 * ======================
 * Business logic layer for notifications.
 *
 * createNotification() is the single entry point called by every other service
 * (intakeService, incidentOperationsService, etc.) when it needs to fire a notification.
 *
 * After the DB transaction commits, we enqueue each email_outbox row into BullMQ.
 * Enqueue errors are caught and logged — they never fail the notification creation.
 * If an enqueue is missed, the startup recovery sweep in emailQueueWorker.js will
 * re-enqueue any pending rows that were left behind.
 */

import {
  countUnreadByRecipientUserId,
  insertNotificationWithRecipients,
  listNotificationsByRecipientUserId,
  markNotificationRecipientRead,
} from "../repositories/notificationRepo.js";
import { enqueueEmail } from "../queues/emailQueue.js";


export async function createNotification(params) {
  // DB work — returns outboxIds so we can enqueue after the transaction commits.
  const result = await insertNotificationWithRecipients({
    notificationType:  params.notificationType,
    templateCode:      params.templateCode,
    templateVars:      params.templateVars      ?? {},
    fallbackTitle:     params.fallbackTitle,
    fallbackBody:      params.fallbackBody,
    entityType:        params.entityType        ?? null,
    entityId:          params.entityId          ?? null,
    recipientUserIds:  params.recipientUserIds,
    createdByUserId:   params.createdByUserId   ?? null,
    deliveryChannel:   params.deliveryChannel,
  });

  // Enqueue each outbox row into BullMQ now that the transaction has committed.
  // Loop individually so one failed enqueue does not block the others.
  for (const outboxId of result.outboxIds) {
    try {
      await enqueueEmail(outboxId);
    } catch (err) {
      // Log only — the row stays 'pending' in the DB.
      // The startup recovery sweep will re-enqueue it on next worker start.
      console.error(
        `[notificationService] Failed to enqueue outboxId=${outboxId}:`,
        err?.message ?? err,
      );
    }
  }

  return result;
}


export async function listNotificationsForUser(actorUserId, options = {}) {
  return listNotificationsByRecipientUserId(actorUserId, {
    unreadOnly: options.unreadOnly ?? false,
    limit:      options.limit      ?? 20,
    offset:     options.offset     ?? 0,
  });
}


export async function getUnreadCountForUser(actorUserId) {
  return countUnreadByRecipientUserId(actorUserId);
}


export async function markAsRead(actorUserId, notificationRecipientId) {
  await markNotificationRecipientRead(notificationRecipientId, actorUserId);
}