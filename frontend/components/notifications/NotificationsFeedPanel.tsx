"use client";

import { NotificationListItem } from "@/components/notifications/NotificationListItem";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import type { NotificationItem } from "@/types/notifications";

export type NotificationsFeedPanelProps = {
  title: string;
  unreadCount?: number;
  items: NotificationItem[];
  variant: "preview" | "page";
  isLoading?: boolean;
  error?: string | null;
  emptyMessage?: string;
  markingReadId?: number | null;
  className?: string;
  listClassName?: string;
  onRetry?: () => void;
  onMarkRead?: (notification: NotificationItem) => void;
};

function NotificationRowSkeleton() {
  return (
    <div className="border-b border-slate-100 px-4 py-3" aria-hidden>
      <div className="h-3 w-24 animate-pulse rounded bg-slate-100" />
      <div className="mt-2 h-4 w-3/4 animate-pulse rounded bg-slate-100" />
      <div className="mt-2 h-3 w-full animate-pulse rounded bg-slate-100" />
    </div>
  );
}

export function NotificationsFeedPanel({
  title,
  unreadCount = 0,
  items,
  variant,
  isLoading = false,
  error = null,
  emptyMessage = "No notifications yet.",
  markingReadId = null,
  className = "",
  listClassName = "",
  onRetry,
  onMarkRead,
}: NotificationsFeedPanelProps) {
  const isPage = variant === "page";

  return (
    <section
      className={`flex min-h-0 flex-col overflow-hidden rounded-2xl border border-[#002D62]/10 bg-white shadow-sm shadow-[#002D62]/5 lg:min-h-0 ${className}`.trim()}
      aria-label={title}
    >
      <header className="flex shrink-0 items-center justify-between gap-3 border-b border-[#002D62]/10 px-4 py-3">
        <h3 className="text-sm font-semibold text-[#002D62]">{title}</h3>
        {unreadCount > 0 ? (
          <span className="shrink-0 rounded-full bg-[#EFF6FF] px-3 py-1 text-xs font-semibold text-[#002D62]">
            {unreadCount} unread
          </span>
        ) : null}
      </header>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {error ? (
          <div className="space-y-3 px-4 py-4">
            <ErrorAlert message={error} />
            {onRetry ? (
              <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
                Retry
              </Button>
            ) : null}
          </div>
        ) : isLoading && items.length === 0 ? (
          <div className="min-h-0 flex-1 overflow-hidden">
            {Array.from({ length: isPage ? 5 : 3 }).map((_, index) => (
              <NotificationRowSkeleton key={index} />
            ))}
          </div>
        ) : items.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-slate-500">
            {emptyMessage}
          </p>
        ) : (
          <ul
            className={`min-h-0 flex-1 overflow-y-auto overscroll-y-contain ${listClassName}`.trim()}
          >
            {items.map((notification) => (
              <li key={notification.notification_recipient_id}>
                <NotificationListItem
                  notification={notification}
                  variant={variant}
                  isMarkingRead={
                    markingReadId === notification.notification_recipient_id
                  }
                  onMarkRead={onMarkRead}
                />
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
