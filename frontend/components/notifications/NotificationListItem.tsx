"use client";

import type { MouseEvent } from "react";
import { getDispatcherNotificationRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { formatNotificationType } from "@/lib/format-notification-type";
import { isNotificationUnread } from "@/lib/notification-utils";
import { formatRelativeAge } from "@/lib/format-relative-age";
import { Button } from "@/components/ui/Button";
import type { NotificationItem } from "@/types/notifications";

export type NotificationListItemProps = {
  notification: NotificationItem;
  variant: "preview" | "page";
  isMarkingRead?: boolean;
  onMarkRead?: (notification: NotificationItem) => void;
};

export function NotificationListItem({
  notification,
  variant,
  isMarkingRead = false,
  onMarkRead,
}: NotificationListItemProps) {
  const unread = isNotificationUnread(notification);
  const isPreview = variant === "preview";

  const handleMarkRead = (event: MouseEvent) => {
    event.stopPropagation();
    if (!unread || !onMarkRead) return;
    onMarkRead(notification);
  };

  if (isPreview) {
    return (
      <article
        className={`relative flex cursor-default gap-2 px-3 py-2 ${getDispatcherNotificationRowClasses(unread)}`}
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span
              className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                unread ? "bg-[#002D62]" : "bg-transparent"
              }`}
              aria-hidden
            />
            <p className="truncate text-[11px] font-medium uppercase tracking-wide text-slate-500">
              {formatNotificationType(notification.notification_type)}
            </p>
          </div>
          <h3
            className={`mt-0.5 line-clamp-1 text-sm font-semibold leading-snug ${
              unread ? "text-slate-900" : "text-slate-700"
            }`}
          >
            {notification.title || "NIERS notification"}
          </h3>
          <p
            className={`mt-0.5 line-clamp-1 text-sm leading-snug ${
              unread ? "text-slate-600" : "text-slate-500"
            }`}
          >
            {notification.body || "-"}
          </p>
          <p className="mt-0.5 text-xs text-slate-500">
            {formatRelativeAge(notification.created_at)}
          </p>
        </div>

        {unread && onMarkRead ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 shrink-0 self-start px-2 text-xs"
            isLoading={isMarkingRead}
            onClick={handleMarkRead}
          >
            Mark read
          </Button>
        ) : null}
      </article>
    );
  }

  return (
    <article
      className={`relative flex cursor-default gap-2 border-b border-[#002D62]/10 px-4 py-3 last:border-b-0 ${getDispatcherNotificationRowClasses(unread)}`}
    >
      <div
        className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
          unread ? "bg-[#002D62]" : "bg-transparent"
        }`}
        aria-hidden
      />

      <div className="min-w-0 flex-1">
        <p className="text-xs font-semibold uppercase tracking-wide text-[#42547A]">
          {formatNotificationType(notification.notification_type)}
        </p>
        <h3
          className={`mt-0.5 text-sm font-semibold ${
            unread ? "text-slate-900" : "text-slate-700"
          }`}
        >
          {notification.title || "NIERS notification"}
        </h3>
        <p
          className={`mt-0.5 line-clamp-2 text-sm ${
            unread ? "text-slate-600" : "text-slate-500"
          }`}
        >
          {notification.body || "-"}
        </p>
        <p className="mt-1 text-xs text-slate-500">
          {formatRelativeAge(notification.created_at)}
        </p>
      </div>

      {unread && onMarkRead ? (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-8 shrink-0 self-start px-2.5 text-xs"
          isLoading={isMarkingRead}
          onClick={handleMarkRead}
        >
          Mark read
        </Button>
      ) : null}
    </article>
  );
}
