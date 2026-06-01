"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { NotificationsFeedPanel } from "@/components/notifications/NotificationsFeedPanel";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageLoading } from "@/components/ui/StatusState";
import { clearAuthSession, getAuthSession, type UserRole } from "@/lib/auth-store";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import {
  dispatchNotificationsUpdated,
  sortNotificationsNewestFirst,
} from "@/lib/notification-utils";
import {
  getMyNotifications,
  getUnreadNotificationCount,
  markNotificationAsRead,
} from "@/lib/notifications-api";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { NotificationItem } from "@/types/notifications";

const FULL_LIST_LIMIT = 50;

function useIsDispatcherShellRole(role: UserRole) {
  return role === "dispatcher" || role === "system_admin";
}

export default function NotificationsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard();
  const [role, setRole] = useState<UserRole>("citizen");
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [markingReadId, setMarkingReadId] = useState<number | null>(null);

  const isDispatcherShell = useIsDispatcherShellRole(role);

  useEffect(() => {
    setRole(getAuthSession().userRole);
  }, []);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const loadNotifications = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [listData, unreadData] = await Promise.all([
        getMyNotifications({ limit: FULL_LIST_LIMIT, offset: 0 }),
        getUnreadNotificationCount(),
      ]);
      setNotifications(
        sortNotificationsNewestFirst(listData.notifications ?? []),
      );
      setUnreadCount(Number(unreadData.unreadCount ?? 0));
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
  }, []);

  useEffect(() => {
    if (isChecking) return;
    void loadNotifications();
  }, [isChecking, loadNotifications]);

  const handleMarkAsRead = async (notification: NotificationItem) => {
    if (notification.read_at) return;

    setMarkingReadId(notification.notification_recipient_id);
    setError(null);

    try {
      await markNotificationAsRead(notification.notification_recipient_id);
      const readAt = new Date().toISOString();
      setNotifications((current) =>
        current.map((item) =>
          item.notification_recipient_id === notification.notification_recipient_id
            ? { ...item, read_at: readAt }
            : item,
        ),
      );
      setUnreadCount((count) => Math.max(0, count - 1));
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

  if (isChecking) {
    return <PageLoading label="Loading notifications" />;
  }

  const pageBody = (
    <div className="flex min-h-0 flex-1 flex-col gap-4 lg:overflow-hidden">
      <header className="flex shrink-0 flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-slate-900">Notifications</h2>
          <p className="mt-0.5 text-sm text-slate-600">
            Updates related to your reports, cases and incident activity.
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="shrink-0"
          onClick={() => void loadNotifications()}
          disabled={isLoading}
          isLoading={isLoading}
        >
          {isLoading ? "Refreshing…" : "Refresh"}
        </Button>
      </header>

      {error ? <ErrorAlert message={error} /> : null}

      <NotificationsFeedPanel
        className="min-h-0 flex-1"
        title="All Notifications"
        unreadCount={unreadCount}
        items={notifications}
        variant="page"
        isLoading={isLoading}
        error={null}
        markingReadId={markingReadId}
        onMarkRead={(item) => void handleMarkAsRead(item)}
      />
    </div>
  );

  if (isDispatcherShell) {
    return (
      <DashboardLayout
        title={DISPATCHER_DASHBOARD_TITLE}
        subtitle={DISPATCHER_DASHBOARD_SUBTITLE}
        onLogout={handleLogout}
        hideSidebar
        showHealthBadge={false}
        contentClassName="flex min-h-0 flex-col lg:h-[calc(100vh-11.5rem)]"
      >
        <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0">
          {pageBody}
        </DispatcherOpsShell>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout
      title="Notifications"
      subtitle="Updates related to your reports, cases and incident activity."
      onLogout={handleLogout}
      contentClassName="flex min-h-0 flex-col lg:h-[calc(100vh-11.5rem)]"
    >
      {pageBody}
    </DashboardLayout>
  );
}
