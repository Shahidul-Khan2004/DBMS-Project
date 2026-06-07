"use client";

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { usePathname, useRouter } from "next/navigation";
import { User, X } from "lucide-react";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { apiJson } from "@/lib/api";
import {
  formatPhoneOrNotAdded,
  getSecondaryPhoneNumberFromUser,
} from "@/lib/profile-api";
import { getAuthz } from "@/lib/auth-store";
import {
  computeNotificationPopoverPosition,
  type PopoverPosition,
} from "@/lib/notification-popover-position";
import {
  dispatchProfilePopoverOpened,
  NOTIFICATION_POPOVER_OPENED_EVENT,
} from "@/lib/notification-utils";
import type { AuthzInfo, LoginResponse } from "@/types/auth";

const PROFILE_POPOVER_ID = "profile-menu-popover";
const MOBILE_MEDIA = "(max-width: 767px)";

type MeResponse = {
  user: LoginResponse["user"];
  authz?: AuthzInfo;
};

function formatRoleLabel(value: string) {
  return value
    .replace(/_/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function getStoredUser() {
  const raw = sessionStorage.getItem("loggedInUser");
  if (!raw) return null;

  try {
    return JSON.parse(raw) as LoginResponse["user"];
  } catch {
    return null;
  }
}

function SummaryItem({
  label,
  value,
  children,
}: {
  label: string;
  value?: string | null;
  children?: ReactNode;
}) {
  if (!children && !value) return null;

  return (
    <div className="min-w-0">
      <dt className="text-xs font-semibold uppercase text-slate-500">{label}</dt>
      <dd className="mt-1 break-words text-sm font-medium text-slate-900">
        {children ?? value}
      </dd>
    </div>
  );
}

export function ProfileMenu({ compactOnMobile = false }: { compactOnMobile?: boolean }) {
  const router = useRouter();
  const pathname = usePathname();
  const anchorRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [authz, setAuthz] = useState<AuthzInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isMobile, setIsMobile] = useState(false);
  const [desktopPosition, setDesktopPosition] = useState<PopoverPosition | null>(null);

  const updateDesktopPosition = useCallback(() => {
    const button = buttonRef.current;
    if (!button) return;
    setDesktopPosition(
      computeNotificationPopoverPosition(button.getBoundingClientRect()),
    );
  }, []);

  const loadProfile = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    const storedUser = getStoredUser();
    const storedAuthz = getAuthz();
    if (storedUser) setUser(storedUser);
    if (storedAuthz) setAuthz(storedAuthz);

    try {
      const data = await apiJson<MeResponse>("/users/me");
      setUser(data.user);
      setAuthz(data.authz ?? storedAuthz ?? null);
      sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
    } catch (err) {
      if (!storedUser) {
        setError(
          err instanceof Error ? err.message : "Could not load profile summary.",
        );
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    function handleNotificationOpened() {
      setOpen(false);
    }

    window.addEventListener(
      NOTIFICATION_POPOVER_OPENED_EVENT,
      handleNotificationOpened,
    );
    return () =>
      window.removeEventListener(
        NOTIFICATION_POPOVER_OPENED_EVENT,
        handleNotificationOpened,
      );
  }, []);

  useEffect(() => {
    if (!open) return;
    void loadProfile();
  }, [open, loadProfile]);

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
    if (isMobile) {
      previousOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    panelRef.current?.focus();

    return () => {
      if (isMobile) {
        document.body.style.overflow = previousOverflow;
      }
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, isMobile]);

  useEffect(() => {
    if (!open) return;

    function handlePointerDown(event: MouseEvent) {
      const target = event.target as Node;
      if (anchorRef.current?.contains(target)) return;
      if (panelRef.current?.contains(target)) return;
      setOpen(false);
    }

    document.addEventListener("mousedown", handlePointerDown);
    return () => document.removeEventListener("mousedown", handlePointerDown);
  }, [open]);

  const handleToggle = () => {
    setOpen((current) => {
      const nextOpen = !current;
      if (nextOpen) {
        dispatchProfilePopoverOpened();
      }
      return nextOpen;
    });
  };

  const handleViewDetails = () => {
    setOpen(false);
    router.push("/dashboard/profile");
  };

  const roleLabel = authz?.roleCodes?.length
    ? authz.roleCodes.map(formatRoleLabel).join(", ")
    : "";
  const isOnProfilePage = pathname === "/dashboard/profile";
  const panelStyle: CSSProperties | undefined =
    !isMobile && desktopPosition
      ? {
          top: desktopPosition.top,
          left: desktopPosition.left,
          width: desktopPosition.width,
          maxHeight: desktopPosition.maxHeight,
        }
      : undefined;

  const content = open ? (
    <>
      {isMobile ? (
        <button
          type="button"
          className="fixed inset-0 z-[60] cursor-pointer bg-black/40"
          aria-label="Close profile summary"
          onClick={() => setOpen(false)}
        />
      ) : null}

      <div
        ref={panelRef}
        id={PROFILE_POPOVER_ID}
        role="dialog"
        aria-modal="true"
        aria-label="Profile summary"
        tabIndex={-1}
        style={panelStyle}
        className={
          isMobile
            ? "fixed inset-x-4 bottom-4 z-[70] flex max-h-[min(70vh,32rem)] flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-xl outline-none"
            : "fixed z-[70] flex flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-xl outline-none"
        }
      >
        <header className="flex shrink-0 items-center justify-between gap-2 border-b border-slate-100 px-3 py-2.5">
          <h2 className="text-sm font-semibold text-slate-900">
            Profile Summary
          </h2>
          {isMobile ? (
            <button
              type="button"
              className="inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-full text-slate-600 transition-colors duration-150 hover:bg-slate-100 active:bg-slate-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
              aria-label="Close profile summary"
              onClick={() => setOpen(false)}
            >
              <X className="h-4 w-4" aria-hidden />
            </button>
          ) : null}
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-3 py-3">
          {error ? (
            <ErrorAlert message={error} />
          ) : isLoading && !user ? (
            <div className="space-y-2" aria-busy="true">
              <div className="h-5 w-40 animate-pulse rounded bg-slate-100" />
              <div className="h-4 w-56 animate-pulse rounded bg-slate-100" />
              <div className="h-4 w-32 animate-pulse rounded bg-slate-100" />
            </div>
          ) : user ? (
            <dl className="space-y-3">
              <SummaryItem label="Full Name" value={user.full_name} />
              <SummaryItem label="Email" value={user.email} />
              <SummaryItem label="Phone" value={user.phone_number} />
              <SummaryItem
                label="SECONDARY PHONE"
                value={formatPhoneOrNotAdded(
                  getSecondaryPhoneNumberFromUser(user),
                )}
              />
              <SummaryItem label="Role" value={roleLabel} />
              {user.account_status ? (
                <SummaryItem label="Account Status">
                  <Badge tone={user.account_status}>
                    {formatBadgeLabel(user.account_status)}
                  </Badge>
                </SummaryItem>
              ) : null}
            </dl>
          ) : (
            <p className="py-3 text-sm text-slate-500">
              Profile summary is unavailable.
            </p>
          )}
        </div>

        <footer className="shrink-0 border-t border-slate-100 p-2">
          <button
            type="button"
            className="w-full cursor-pointer rounded-lg px-3 py-2 text-sm font-medium text-[#002D62] transition-colors duration-150 hover:bg-[#EFF6FF] hover:text-[#001F4A] active:bg-[#DCEBFF] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
            onClick={handleViewDetails}
          >
            View Details
          </button>
        </footer>
      </div>
    </>
  ) : null;

  return (
    <div ref={anchorRef} className="relative">
      <button
        ref={buttonRef}
        type="button"
        onClick={handleToggle}
        aria-expanded={open}
        aria-controls={PROFILE_POPOVER_ID}
        aria-haspopup="dialog"
        className={`inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-xl border bg-white text-sm font-bold text-[#002D62] transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] ${
          compactOnMobile
            ? "w-10 px-0 min-[480px]:w-[6.5rem] min-[480px]:px-3"
            : "w-[6.5rem] px-3"
        } ${
          isOnProfilePage
            ? "border-[#002D62] bg-[#002D62]/10 ring-2 ring-[#002D62]/20 hover:bg-[#002D62]/15"
            : "border-[#0B3FE8] hover:bg-[#EFF6FF]"
        }`}
      >
        <User className="h-4 w-4" aria-hidden />
        <span className={compactOnMobile ? "sr-only min-[480px]:not-sr-only" : ""}>
          Profile
        </span>
      </button>
      {content ? createPortal(content, document.body) : null}
    </div>
  );
}
