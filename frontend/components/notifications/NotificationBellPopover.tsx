"use client";

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/navigation";
import { X } from "lucide-react";
import { NotificationListItem } from "@/components/notifications/NotificationListItem";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import {
  computeNotificationPopoverPosition,
  type PopoverPosition,
} from "@/lib/notification-popover-position";
import {
  dispatchNotificationsUpdated,
  sortNotificationsNewestFirst,
} from "@/lib/notification-utils";
import {
  getMyNotifications,
  markNotificationAsRead,
} from "@/lib/notifications-api";
import type { NotificationItem } from "@/types/notifications";

export const NOTIFICATION_BELL_POPOVER_ID = "notification-bell-popover";

const MOBILE_MEDIA = "(max-width: 767px)";

export type NotificationBellPopoverProps = {
  open: boolean;
  unreadCount: number;
  onClose: () => void;
  anchorRef: React.RefObject<HTMLDivElement | null>;
  bellRef: React.RefObject<HTMLButtonElement | null>;
};

export function NotificationBellPopover({
  open,
  unreadCount,
  onClose,
  anchorRef,
  bellRef,
}: NotificationBellPopoverProps) {
  const router = useRouter();
  const panelRef = useRef<HTMLDivElement>(null);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [markingReadId, setMarkingReadId] = useState<number | null>(null);
  const [isMobile, setIsMobile] = useState(false);
  const [desktopPosition, setDesktopPosition] = useState<PopoverPosition | null>(
    null,
  );

  const updateDesktopPosition = useCallback(() => {
    const bell = bellRef.current;
    if (!bell) return;
    setDesktopPosition(
      computeNotificationPopoverPosition(bell.getBoundingClientRect()),
    );
  }, [bellRef]);

  const loadPreview = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await getMyNotifications({ limit: 5, offset: 0 });
      setNotifications(
        sortNotificationsNewestFirst(data.notifications ?? []),
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not load notifications.",
      );
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    void loadPreview();
  }, [open, loadPreview]);

  useLayoutEffect(() => {
    if (!open) {
      setIsMobile(false);
      return;
    }

    const media = window.matchMedia(MOBILE_MEDIA);
    const syncMobile = () => setIsMobile(media.matches);
    syncMobile();
    media.addEventListener("change", syncMobile);

    return () => media.removeEventListener("change", syncMobile);
  }, [open]);

  useLayoutEffect(() => {
    if (!open || isMobile) {
      setDesktopPosition(null);
      return;
    }

    updateDesktopPosition();

    const onViewportChange = () => updateDesktopPosition();
    window.addEventListener("resize", onViewportChange);
    window.addEventListener("scroll", onViewportChange, true);

    return () => {
      window.removeEventListener("resize", onViewportChange);
      window.removeEventListener("scroll", onViewportChange, true);
    };
  }, [open, isMobile, updateDesktopPosition]);

  useEffect(() => {
    if (!open) return;

    let previousOverflow = "";

    const applyBodyLock = () => {
      if (!isMobile) return;
      previousOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
    };

    const releaseBodyLock = () => {
      if (!isMobile) return;
      document.body.style.overflow = previousOverflow;
    };

    applyBodyLock();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    panelRef.current?.focus();

    return () => {
      releaseBodyLock();
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onClose, isMobile]);

  useEffect(() => {
    if (!open) return;

    function handlePointerDown(event: MouseEvent) {
      const target = event.target as Node;
      if (anchorRef.current?.contains(target)) return;
      if (panelRef.current?.contains(target)) return;
      onClose();
    }

    document.addEventListener("mousedown", handlePointerDown);
    return () => document.removeEventListener("mousedown", handlePointerDown);
  }, [open, onClose, anchorRef]);

  const handleMarkRead = async (notification: NotificationItem) => {
    if (notification.read_at) return;

    setMarkingReadId(notification.notification_recipient_id);
    setError(null);

    try {
      await markNotificationAsRead(notification.notification_recipient_id);
      setNotifications((current) =>
        current.map((item) =>
          item.notification_recipient_id ===
          notification.notification_recipient_id
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

  const handleViewAll = () => {
    onClose();
    router.push("/dashboard/notifications");
  };

  if (!open) return null;

  const headerUnread =
    unreadCount > 0 ? (
      <span className="text-sm font-medium text-slate-600">
        {unreadCount > 99 ? "99+ unread" : `${unreadCount} unread`}
      </span>
    ) : null;

  const panelStyle: React.CSSProperties | undefined =
    !isMobile && desktopPosition
      ? {
          top: desktopPosition.top,
          left: desktopPosition.left,
          width: desktopPosition.width,
          maxHeight: desktopPosition.maxHeight,
        }
      : undefined;

  const content = (
    <>
      {isMobile ? (
        <button
          type="button"
          className="fixed inset-0 z-[60] cursor-pointer bg-black/40"
          aria-label="Close notifications"
          onClick={onClose}
        />
      ) : null}

      <div
        ref={panelRef}
        id={NOTIFICATION_BELL_POPOVER_ID}
        role="dialog"
        aria-modal="true"
        aria-label="Notifications preview"
        tabIndex={-1}
        style={panelStyle}
        className={
          isMobile
            ? "fixed inset-x-4 bottom-4 z-[70] flex max-h-[min(70vh,32rem)] flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-xl outline-none"
            : "fixed z-[70] flex flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-xl outline-none"
        }
      >
        <header className="flex shrink-0 items-center justify-between gap-2 border-b border-slate-100 px-3 py-2.5">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold text-slate-900">
              Notifications
            </h2>
            {headerUnread}
          </div>
          {isMobile ? (
            <button
              type="button"
              className="inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-full text-slate-600 transition-colors duration-150 hover:bg-slate-100 active:bg-slate-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
              aria-label="Close notifications"
              onClick={onClose}
            >
              <X className="h-4 w-4" aria-hidden />
            </button>
          ) : null}
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain">
          {error ? (
            <div className="space-y-3 px-3 py-3">
              <ErrorAlert message={error} />
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => void loadPreview()}
              >
                Retry
              </Button>
            </div>
          ) : isLoading && notifications.length === 0 ? (
            <div className="space-y-2 px-3 py-3" aria-busy="true">
              {Array.from({ length: 3 }).map((_, index) => (
                <div
                  key={index}
                  className="h-14 animate-pulse rounded-lg bg-slate-100"
                  aria-hidden
                />
              ))}
            </div>
          ) : notifications.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-slate-500">
              No notifications yet.
            </p>
          ) : (
            <ul>
              {notifications.map((notification) => (
                <li key={notification.notification_recipient_id}>
                  <NotificationListItem
                    notification={notification}
                    variant="preview"
                    isMarkingRead={
                      markingReadId === notification.notification_recipient_id
                    }
                    onMarkRead={(item) => void handleMarkRead(item)}
                  />
                </li>
              ))}
            </ul>
          )}
        </div>

        <footer className="shrink-0 border-t border-slate-100 p-2">
          <button
            type="button"
            className="w-full cursor-pointer rounded-lg px-3 py-2 text-sm font-medium text-[#002D62] transition-colors duration-150 hover:bg-[#EFF6FF] hover:text-[#001F4A] active:bg-[#DCEBFF] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
            onClick={handleViewAll}
          >
            View all notifications →
          </button>
        </footer>
      </div>
    </>
  );

  return createPortal(content, document.body);
}
