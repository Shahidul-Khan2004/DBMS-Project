/**
 * notificationService.js
 * ======================
 * Business logic layer for notifications.
 *
 * createNotification() is the single entry point called by every other service
 * (intakeService, incidentOperationsService, etc.) when it needs to fire a notification.
 *
 * Template resolution happens inside notificationRepo.insertNotificationWithRecipients():
 *   - templateCode (e.g. 'intake_received') is combined with the channel suffix
 *     ('__in_app' or '__email') to look up a notification_templates row
 *   - templateVars (e.g. { report_code: 'IR-...' }) are interpolated into the template
 *   - fallbackTitle / fallbackBody are used when no active template is found
 *
 * Callers must always wrap createNotification() in try/catch — a notification
 * failure must never break the primary operation that triggered it.
 */

import {
  countUnreadByRecipientUserId,
  insertNotificationWithRecipients,
  listNotificationsByRecipientUserId,
  markNotificationRecipientRead,
} from "../repositories/notificationRepo.js";

/**
 * Creates a notification and queues all delivery records.
 *
 * @param {object}   params
 * @param {string}   params.notificationType
 *   Must match the notifications.notification_type DB ENUM:
 *   'case_reply' | 'case_resolved' | 'case_escalated' |
 *   'incident_update' | 'dispatch_update' | 'relief_update' | 'blood_request_update'
 *
 * @param {string}   params.templateCode
 *   Base template code WITHOUT channel suffix — e.g. 'intake_received'.
 *   The repo appends '__in_app' and '__email' automatically.
 *   Must match a template_code in notification_templates.
 *
 * @param {Record<string,string>} params.templateVars
 *   Key/value map of {{placeholder}} replacements, e.g.:
 *   { report_code: 'IR-ABC123', case_code: 'SC-XYZ' }
 *
 * @param {string}   params.fallbackTitle   - Title used when template not found
 * @param {string}   params.fallbackBody    - Body used when template not found
 * @param {string|null}  params.entityType
 * @param {number|null}  params.entityId
 * @param {number[]} params.recipientUserIds
 * @param {number|null}  params.createdByUserId
 * @param {'in_app'|'email'|'both'} params.deliveryChannel
 *
 * @returns {Promise<{ notificationId: number, recipientCount: number }>}
 */
export async function createNotification(params) {
  return insertNotificationWithRecipients({
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
}

/**
 * Returns a paginated list of in_app notifications for the authenticated user.
 * Called by GET /notifications/my.
 *
 * @param {number} actorUserId
 * @param {object} [options]
 * @param {boolean} [options.unreadOnly=false]
 * @param {number}  [options.limit=20]
 * @param {number}  [options.offset=0]
 * @returns {Promise<object[]>}
 */
export async function listNotificationsForUser(actorUserId, options = {}) {
  return listNotificationsByRecipientUserId(actorUserId, {
    unreadOnly: options.unreadOnly ?? false,
    limit:      options.limit      ?? 20,
    offset:     options.offset     ?? 0,
  });
}

/**
 * Returns the unread in_app notification count for the authenticated user.
 * Called by GET /notifications/my/unread-count.
 *
 * @param {number} actorUserId
 * @returns {Promise<number>}
 */
export async function getUnreadCountForUser(actorUserId) {
  return countUnreadByRecipientUserId(actorUserId);
}

/**
 * Marks one notification_recipients row as read.
 * Ownership enforced inside the repo.
 * Called by PATCH /notifications/:notificationRecipientId/read.
 *
 * @param {number} actorUserId
 * @param {number} notificationRecipientId
 * @returns {Promise<void>}
 */
export async function markAsRead(actorUserId, notificationRecipientId) {
  await markNotificationRecipientRead(notificationRecipientId, actorUserId);
}