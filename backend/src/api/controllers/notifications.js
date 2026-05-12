/**
 * controllers/notifications.js
 * =============================
 * Thin HTTP handlers for notification endpoints.
 *
 * Conventions followed (matches every other controller in this project):
 *   - No try/catch — errors bubble up to the global errorHandler middleware
 *   - No business logic — all decisions live in notificationService
 *   - Reads validated data from req.validated.query / req.validated.params
 *     with fallback to req.query / req.params (matches operationsIncidents.js pattern)
 *   - req.actorUserId is the internal integer user id set by requireAuth middleware
 */

import * as notificationService from "../../services/notificationService.js";

/**
 * GET /notifications/my
 *
 * Returns the authenticated user's notifications, newest first.
 * Supports optional query params: unread_only, limit, offset.
 *
 * Response: { notifications: [...] }
 */
export async function getMyNotifications(req, res) {
  const query = req.validated?.query ?? req.query;

  const notifications = await notificationService.listNotificationsForUser(
    req.actorUserId,
    {
      unreadOnly: query.unread_only ?? false,
      limit:      query.limit       ?? 20,
      offset:     query.offset      ?? 0,
    },
  );

  res.status(200).json({ notifications });
}

/**
 * GET /notifications/my/unread-count
 *
 * Returns the count of unread notifications for the authenticated user.
 *
 * Response: { unreadCount: N }
 */
export async function getUnreadCount(req, res) {
  const unreadCount = await notificationService.getUnreadCountForUser(req.actorUserId);
  res.status(200).json({ unreadCount });
}

/**
 * PATCH /notifications/:notificationRecipientId/read
 *
 * Marks a single notification as read for the authenticated user.
 * Returns 404 if the notification does not exist or belongs to another user.
 * Idempotent — calling it on an already-read notification is safe.
 *
 * Response: { message: "Notification marked as read" }
 */
export async function markNotificationRead(req, res) {
  const params = req.validated?.params ?? req.params;

  await notificationService.markAsRead(
    req.actorUserId,
    params.notificationRecipientId,
  );

  res.status(200).json({ message: "Notification marked as read" });
}