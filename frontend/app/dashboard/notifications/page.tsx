"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { NotificationsFeedPanel } from "@/components/notifications/NotificationsFeedPanel";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageLoading } from "@/components/ui/StatusState";
import { OPS_DASHBOARD_CONTENT_CLASS } from "@/lib/dashboard-viewport";
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

function getDashboardHref(role: UserRole) {
  if (role === "dispatcher") return "/dashboard/dispatcher";
  if (role === "system_admin") return "/dashboard/admin";
  if (role === "agency_representative") return "/dashboard/agency";
  return "/dashboard/citizen";
}

function getBackLabel(role: UserRole) {
  if (role === "dispatcher" || role === "system_admin") {
    return "Back to Command Center";
  }

  return "Back to Dashboard";
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
    <div
      className={`flex min-h-0 flex-1 flex-col gap-4 lg:overflow-hidden ${
        isDispatcherShell ? "" : "mx-auto w-full max-w-5xl"
      }`.trim()}
    >
      {role !== "citizen" ? (
        <div className="flex shrink-0 justify-start">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="h-9 shrink-0 rounded-full border border-[#002D62]/15 bg-white px-3 text-[#002D62] shadow-sm shadow-[#002D62]/5"
            onClick={() => router.push(getDashboardHref(role))}
          >
            <ArrowLeft className="h-4 w-4" aria-hidden />
            {getBackLabel(role)}
          </Button>
        </div>
      ) : null}

      {role !== "citizen" ? (
        <header
          className={`flex shrink-0 flex-wrap items-start justify-between gap-3 ${
            isDispatcherShell
              ? ""
              : "rounded-2xl border border-[#002D62]/10 bg-white px-5 py-4 shadow-sm shadow-[#002D62]/5"
          }`.trim()}
        >
          <div className="min-w-0">
            <h2
              className={`text-xl font-semibold ${
                isDispatcherShell ? "text-slate-900" : "text-[#002D62]"
              }`}
            >
              Notifications
            </h2>
            <p
              className={`mt-0.5 text-sm ${
                isDispatcherShell ? "text-slate-600" : "text-[#42547A]"
              }`}
            >
              Updates related to your reports, cases and incident activity.
            </p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-9 shrink-0 rounded-lg px-3"
            onClick={() => void loadNotifications()}
            disabled={isLoading}
            isLoading={isLoading}
          >
            {isLoading ? "Refreshing..." : "Refresh"}
          </Button>
        </header>
      ) : null}

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
        headerActions={
          role === "citizen" ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-9 shrink-0 rounded-lg px-3"
              onClick={() => void loadNotifications()}
              disabled={isLoading}
              isLoading={isLoading}
            >
              {isLoading ? "Refreshing..." : "Refresh"}
            </Button>
          ) : null
        }
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
        contentClassName={OPS_DASHBOARD_CONTENT_CLASS}
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
      showHealthBadge={false}
      contentClassName={OPS_DASHBOARD_CONTENT_CLASS}
    >
      {pageBody}
    </DashboardLayout>
  );
}
