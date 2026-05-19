"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, CheckCircle2, Inbox, RefreshCw } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import {
  NOTIFICATIONS_UPDATED_EVENT,
} from "@/components/notifications/NotificationBell";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  getMyNotifications,
  markNotificationAsRead,
} from "@/lib/notifications-api";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { NotificationItem } from "@/types/notifications";

function sortNewestFirst(notifications: NotificationItem[]) {
  return [...notifications].sort(
    (a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );
}

function dispatchNotificationsUpdated() {
  window.dispatchEvent(new Event(NOTIFICATIONS_UPDATED_EVENT));
}

export default function NotificationsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard();
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [markingReadId, setMarkingReadId] = useState<number | null>(null);
  const [isMarkingAllRead, setIsMarkingAllRead] = useState(false);

  const unreadNotifications = useMemo(
    () => notifications.filter((notification) => !notification.read_at),
    [notifications],
  );
  const unreadCount = unreadNotifications.length;

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function loadNotifications() {
    setIsLoading(true);
    setError(null);

    try {
      const data = await getMyNotifications({ limit: 50, offset: 0 });
      setNotifications(sortNewestFirst(data.notifications ?? []));
      dispatchNotificationsUpdated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading notifications.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    if (isChecking) return;
    void loadNotifications();
  }, [isChecking]);

  const handleMarkAsRead = async (notification: NotificationItem) => {
    if (notification.read_at || isMarkingAllRead) return;

    setMarkingReadId(notification.notification_recipient_id);
    setError(null);

    try {
      await markNotificationAsRead(notification.notification_recipient_id);
      setNotifications((current) =>
        current.map((item) =>
          item.notification_recipient_id === notification.notification_recipient_id
            ? { ...item, read_at: new Date().toISOString() }
            : item,
        ),
      );
      dispatchNotificationsUpdated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not mark notification as read.",
      );
    } finally {
      setMarkingReadId(null);
    }
  };

  const handleMarkAllAsRead = async () => {
    if (unreadNotifications.length === 0) return;

    setIsMarkingAllRead(true);
    setError(null);

    const readAt = new Date().toISOString();
    const results = await Promise.allSettled(
      unreadNotifications.map((notification) =>
        markNotificationAsRead(notification.notification_recipient_id).then(
          () => notification.notification_recipient_id,
        ),
      ),
    );

    const markedIds = new Set(
      results
        .filter((result): result is PromiseFulfilledResult<number> =>
          result.status === "fulfilled",
        )
        .map((result) => result.value),
    );

    if (markedIds.size > 0) {
      setNotifications((current) =>
        current.map((item) =>
          markedIds.has(item.notification_recipient_id)
            ? { ...item, read_at: readAt }
            : item,
        ),
      );
      dispatchNotificationsUpdated();
    }

    if (markedIds.size < unreadNotifications.length) {
      setError("Some notifications could not be marked as read. Please try again.");
    }

    setIsMarkingAllRead(false);
  };

  if (isChecking) {
    return <PageLoading label="Loading notifications" />;
  }

  return (
    <DashboardLayout
      title="Notifications"
      subtitle="Recent NIERS updates for your account"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-2">
            <Badge tone={unreadCount > 0 ? "urgent" : "resolved"}>
              {unreadCount} unread
            </Badge>
            <Badge tone="active">{notifications.length} total</Badge>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void handleMarkAllAsRead()}
              isLoading={isMarkingAllRead}
              disabled={unreadCount === 0 || isLoading}
            >
              <CheckCircle2 className="h-4 w-4" aria-hidden />
              Mark all read
            </Button>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => void loadNotifications()}
              isLoading={isLoading}
              disabled={isMarkingAllRead}
            >
              <RefreshCw className="h-4 w-4" aria-hidden />
              Refresh
            </Button>
          </div>
        </div>

        {error ? <ErrorAlert message={error} /> : null}

        <Card className="shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <Bell className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Notification Center
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  Newest notifications appear first.
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {isLoading ? <LoadingSkeleton lines={5} /> : null}

            {!isLoading && !error && notifications.length === 0 ? (
              <EmptyState
                title="No notifications yet"
                description="Account updates, case changes, and incident alerts will appear here."
                icon={<Inbox className="h-6 w-6" aria-hidden />}
              />
            ) : null}

            {!isLoading && notifications.length > 0 ? (
              <div className="grid gap-4">
                {notifications.map((notification) => {
                  const isUnread = !notification.read_at;

                  return (
                    <article
                      key={notification.notification_recipient_id}
                      className={`rounded-2xl border p-5 shadow-sm ${
                        isUnread
                          ? "border-[#006747]/25 bg-white"
                          : "border-[#002D62]/10 bg-white/75"
                      }`}
                    >
                      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge tone={notification.notification_type}>
                              {formatBadgeLabel(notification.notification_type)}
                            </Badge>
                            <Badge tone={isUnread ? "urgent" : "resolved"}>
                              {isUnread ? "Unread" : "Read"}
                            </Badge>
                          </div>
                          <h3 className="mt-3 text-lg font-semibold text-gray-900">
                            {notification.title || "NIERS notification"}
                          </h3>
                          <p className="mt-2 text-sm leading-6 text-gray-700">
                            {notification.body || "-"}
                          </p>
                        </div>
                        {isUnread ? (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            isLoading={
                              markingReadId ===
                              notification.notification_recipient_id
                            }
                            disabled={isMarkingAllRead}
                            onClick={() => void handleMarkAsRead(notification)}
                            className="shrink-0"
                          >
                            <CheckCircle2 className="h-4 w-4" aria-hidden />
                            Mark read
                          </Button>
                        ) : null}
                      </div>

                      <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-xs text-gray-600">
                        <span>
                          Received {formatBangladeshTime(notification.created_at)}
                        </span>
                        {notification.read_at ? (
                          <span>
                            Read {formatBangladeshTime(notification.read_at)}
                          </span>
                        ) : null}
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
