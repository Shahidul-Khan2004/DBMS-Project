"use client";

import { apiGet, apiPatch } from "@/lib/api";
import type {
  NotificationsResponse,
  UnreadCountResponse,
} from "@/types/notifications";

export function getMyNotifications({
  unreadOnly,
  limit = 50,
  offset = 0,
}: {
  unreadOnly?: boolean;
  limit?: number;
  offset?: number;
} = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });

  if (unreadOnly) {
    params.set("unread_only", "true");
  }

  return apiGet<NotificationsResponse>(`/notifications/my?${params.toString()}`);
}

export function getUnreadNotificationCount() {
  return apiGet<UnreadCountResponse>("/notifications/my/unread-count");
}

export function markNotificationAsRead(notificationRecipientId: number) {
  return apiPatch<{ message: string }>(
    `/notifications/${notificationRecipientId}/read`,
  );
}
