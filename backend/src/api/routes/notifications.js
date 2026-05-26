import express from "express";
import { requireAuth as defaultRequireAuth } from "../middlewares/auth.js";
import {
  getMyNotifications,
  getUnreadCount,
  markNotificationRead,
} from "../controllers/notifications.js";
import {
  validateListNotificationsQuery,
  validateNotificationRecipientIdParam,
} from "../validators/notifications.js";

export function createNotificationsRouter({ requireAuth = defaultRequireAuth } = {}) {
  const router = express.Router();

  router.use(requireAuth);

  router.get("/my", validateListNotificationsQuery, getMyNotifications);
  router.get("/my/unread-count", getUnreadCount);
  router.patch(
    "/:notificationRecipientId/read",
    validateNotificationRecipientIdParam,
    markNotificationRead,
  );

  return router;
}

export default createNotificationsRouter();
