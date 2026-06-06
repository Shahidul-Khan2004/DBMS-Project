import type { NotificationItem } from "@/types/notifications";

export function isNotificationUnread(notification: NotificationItem): boolean {
  return !notification.read_at;
}

export function sortNotificationsNewestFirst(
  notifications: NotificationItem[],
): NotificationItem[] {
  return [...notifications].sort(
    (a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );
}

export const NOTIFICATIONS_UPDATED_EVENT = "niers:notifications-updated";
export const NOTIFICATION_POPOVER_OPENED_EVENT =
  "niers:notification-popover-opened";
export const PROFILE_POPOVER_OPENED_EVENT = "niers:profile-popover-opened";

export function dispatchNotificationsUpdated() {
  window.dispatchEvent(new Event(NOTIFICATIONS_UPDATED_EVENT));
}

export function dispatchNotificationPopoverOpened() {
  window.dispatchEvent(new Event(NOTIFICATION_POPOVER_OPENED_EVENT));
}

export function dispatchProfilePopoverOpened() {
  window.dispatchEvent(new Event(PROFILE_POPOVER_OPENED_EVENT));
}
