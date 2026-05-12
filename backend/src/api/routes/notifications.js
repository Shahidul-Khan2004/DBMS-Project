/**
 * routes/notifications.js
 * ========================
 * Express router for all /notifications endpoints.
 *
 * Mounted in app.js at: app.use("/notifications", notificationsRouter)
 *
 * All routes require authentication (router.use(requireAuth)).
 * No additional role or permission checks — users only access their own data.
 * Ownership enforcement happens at the repo level (SQL WHERE recipient_user_id = ?).
 *
 * Route summary:
 *   GET  /notifications/my                          → getMyNotifications
 *   GET  /notifications/my/unread-count             → getUnreadCount
 *   PATCH /notifications/:notificationRecipientId/read → markNotificationRead
 */

import express from "express";
import { requireAuth } from "../middlewares/auth.js";
import {
  getMyNotifications,
  getUnreadCount,
  markNotificationRead,
} from "../controllers/notifications.js";
import {
  validateListNotificationsQuery,
  validateNotificationRecipientIdParam,
} from "../validators/notifications.js";

const router = express.Router();

/**
 * Applies authentication middleware to all notification routes.
 * Every route below requires a valid Bearer token.
 */
router.use(requireAuth);

/**
 * @route   GET /notifications/my
 * @desc    Returns the authenticated user's notifications, newest first.
 *          Supports optional query params: unread_only, limit, offset.
 * @access  Private
 */
router.get(
  "/my",
  validateListNotificationsQuery,
  getMyNotifications,
);

/**
 * @route   GET /notifications/my/unread-count
 * @desc    Returns the count of unread notifications for the authenticated user.
 * @access  Private
 */
router.get(
  "/my/unread-count",
  getUnreadCount,
);

/**
 * @route   PATCH /notifications/:notificationRecipientId/read
 * @desc    Marks a single notification as read.
 *          Idempotent — safe to call multiple times.
 *          Returns 404 if the notification does not exist or belongs to another user.
 * @access  Private
 */
router.patch(
  "/:notificationRecipientId/read",
  validateNotificationRecipientIdParam,
  markNotificationRead,
);

export default router;