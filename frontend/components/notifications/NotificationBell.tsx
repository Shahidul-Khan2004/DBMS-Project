"use client";

import { usePathname } from "next/navigation";
import { Bell } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  NotificationBellPopover,
  NOTIFICATION_BELL_POPOVER_ID,
} from "@/components/notifications/NotificationBellPopover";
import { ApiError } from "@/lib/api";
import {
  dispatchNotificationPopoverOpened,
  NOTIFICATIONS_UPDATED_EVENT,
  PROFILE_POPOVER_OPENED_EVENT,
} from "@/lib/notification-utils";
import { getUnreadNotificationCount } from "@/lib/notifications-api";

export { NOTIFICATIONS_UPDATED_EVENT };

export function NotificationBell() {
  const pathname = usePathname();
  const anchorRef = useRef<HTMLDivElement>(null);
  const bellRef = useRef<HTMLButtonElement>(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [open, setOpen] = useState(false);

  const handleProfileOpened = () => {
    setOpen(false);
  };

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
    window.addEventListener(PROFILE_POPOVER_OPENED_EVENT, handleProfileOpened);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      window.removeEventListener(NOTIFICATIONS_UPDATED_EVENT, loadUnreadCount);
      window.removeEventListener(PROFILE_POPOVER_OPENED_EVENT, handleProfileOpened);
    };
  }, []);

  const isOnNotificationsPage = pathname === "/dashboard/notifications";
  const visibleCount = unreadCount > 99 ? "99+" : String(unreadCount);

  const handleToggle = () => {
    setOpen((current) => {
      const nextOpen = !current;
      if (nextOpen) {
        dispatchNotificationPopoverOpened();
      }
      return nextOpen;
    });
  };

  const handleClose = () => {
    setOpen(false);
    bellRef.current?.focus();
  };

  return (
    <div ref={anchorRef} className="relative">
      <button
        ref={bellRef}
        type="button"
        onClick={handleToggle}
        aria-expanded={open}
        aria-controls={NOTIFICATION_BELL_POPOVER_ID}
        aria-haspopup="dialog"
        aria-label={
          unreadCount > 0
            ? `${unreadCount} unread notifications`
            : "Notifications"
        }
        className={`relative inline-flex h-10 w-10 cursor-pointer items-center justify-center rounded-2xl border-2 transition-colors duration-150 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] ${
          isOnNotificationsPage
            ? "border-[#002D62] bg-[#002D62]/10 text-[#002D62] ring-2 ring-[#002D62]/20 hover:bg-[#002D62]/15 active:bg-[#002D62]/20"
            : "border-[#002D62]/20 bg-white text-[#002D62] hover:bg-[#EFF6FF] active:bg-[#DCEBFF]"
        }`}
      >
        <Bell className="h-5 w-5" aria-hidden />
        {unreadCount > 0 ? (
          <span className="absolute -right-2 -top-2 min-w-5 rounded-full bg-[#DA291C] px-1.5 py-0.5 text-center text-[10px] font-bold leading-4 text-white ring-2 ring-zinc-200">
            {visibleCount}
          </span>
        ) : null}
      </button>

      <NotificationBellPopover
        open={open}
        unreadCount={unreadCount}
        onClose={handleClose}
        anchorRef={anchorRef}
        bellRef={bellRef}
      />
    </div>
  );
}
