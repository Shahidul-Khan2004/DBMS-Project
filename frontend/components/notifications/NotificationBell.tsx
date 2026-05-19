"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Bell } from "lucide-react";
import { useEffect, useState } from "react";
import { ApiError } from "@/lib/api";
import { getUnreadNotificationCount } from "@/lib/notifications-api";

export const NOTIFICATIONS_UPDATED_EVENT = "niers:notifications-updated";

export function NotificationBell() {
  const pathname = usePathname();
  const [unreadCount, setUnreadCount] = useState(0);

  useEffect(() => {
    let cancelled = false;

    async function loadUnreadCount() {
      try {
        const data = await getUnreadNotificationCount();
        if (!cancelled) {
          setUnreadCount(Number(data.unreadCount ?? 0));
        }
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          setUnreadCount(0);
        }
      }
    }

    void loadUnreadCount();
    const intervalId = window.setInterval(loadUnreadCount, 60000);

    window.addEventListener(NOTIFICATIONS_UPDATED_EVENT, loadUnreadCount);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      window.removeEventListener(NOTIFICATIONS_UPDATED_EVENT, loadUnreadCount);
    };
  }, []);

  const isActive = pathname === "/dashboard/notifications";
  const visibleCount = unreadCount > 99 ? "99+" : String(unreadCount);

  return (
    <Link
      href="/dashboard/notifications"
      className={`relative inline-flex h-10 w-10 items-center justify-center rounded-2xl border-2 transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] ${
        isActive
          ? "border-[#002D62] bg-[#002D62] text-white"
          : "border-[#002D62]/20 bg-white text-[#002D62] hover:bg-[#EFF6FF]"
      }`}
      aria-label={
        unreadCount > 0
          ? `${unreadCount} unread notifications`
          : "Notifications"
      }
      title="Notifications"
    >
      <Bell className="h-5 w-5" aria-hidden />
      {unreadCount > 0 ? (
        <span className="absolute -right-2 -top-2 min-w-5 rounded-full bg-[#DA291C] px-1.5 py-0.5 text-center text-[10px] font-bold leading-4 text-white ring-2 ring-zinc-200">
          {visibleCount}
        </span>
      ) : null}
    </Link>
  );
}
