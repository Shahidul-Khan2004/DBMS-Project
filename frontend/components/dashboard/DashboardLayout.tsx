"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect, useState } from "react";
import { getAuthSession, type UserRole } from "@/lib/auth-store";
import { LogOut, User } from "lucide-react";
import { CitizenNavDrawer } from "@/components/citizen/CitizenNavDrawer";
import { CitizenNavProvider } from "@/components/citizen/CitizenNavContext";
import { CitizenTopNav } from "@/components/citizen/CitizenTopNav";
import { HealthBadge } from "@/components/HealthBadge";
import { ProfileMenu } from "@/components/dashboard/ProfileMenu";
import { CitizenNationalDisasterAlert } from "@/components/national-disaster/CitizenNationalDisasterAlert";
import { OpsNationalDisasterAlertBar } from "@/components/national-disaster/OpsNationalDisasterAlertBar";
import { NotificationBell } from "@/components/notifications/NotificationBell";
import { isOpsDashboardRoute } from "@/lib/dashboard-viewport";

interface DashboardLayoutProps {
  title: string;
  subtitle: string;
  children: React.ReactNode;
  onLogout?: () => void;
  hideSidebar?: boolean;
  showHealthBadge?: boolean;
  /** Applied to the main content children wrapper (e.g. full-height dispatcher pages). */
  contentClassName?: string;
  /** Fill remaining viewport below header/nav (citizen workspace pages). */
  fillViewport?: boolean;
  /** Lock ops dashboard to viewport height on desktop; content scrolls internally. */
  lockViewport?: boolean;
  /** Allow normal document scrolling on desktop ops dashboards (opt-out of lock). */
  allowDocumentScroll?: boolean;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  title,
  subtitle,
  children,
  onLogout,
  hideSidebar = false,
  showHealthBadge = true,
  contentClassName = "",
  fillViewport = false,
  lockViewport = false,
  allowDocumentScroll = false,
}) => {
  const pathname = usePathname();
  const [role, setRole] = useState<UserRole>("citizen");

  useEffect(() => {
    const nextRole = getAuthSession().userRole;
    queueMicrotask(() => setRole(nextRole));
  }, []);

  const isCitizenDashboardRoute = pathname.startsWith("/dashboard/citizen");
  const isCitizenSharedRoute =
    pathname === "/dashboard/profile" || pathname === "/dashboard/notifications";
  const isCitizenDashboardShell =
    role === "citizen" && (isCitizenDashboardRoute || isCitizenSharedRoute);
  const showCitizenTopNav =
    isCitizenDashboardShell && !hideSidebar;
  const isCitizenReportNewPage = pathname === "/dashboard/citizen/report-new";
  const showCitizenReportAction = !isCitizenReportNewPage;
  const useFillViewport = fillViewport && isCitizenDashboardShell;
  const isOpsRole =
    role === "dispatcher" ||
    role === "system_admin" ||
    role === "agency_representative";
  const autoLockOpsViewport =
    isOpsRole &&
    (isOpsDashboardRoute(pathname) ||
      pathname === "/dashboard/notifications");
  const useOpsViewportLock =
    !isCitizenDashboardShell &&
    !allowDocumentScroll &&
    (lockViewport || autoLockOpsViewport);
  const useViewportFill = useFillViewport || useOpsViewportLock;
  const showCitizenDisasterAlert = isCitizenDashboardShell;
  const showOpsDisasterAlert =
    role === "dispatcher" ||
    role === "system_admin" ||
    role === "agency_representative";
  const shellWidthClass = "w-full";
  const shellClassName = isCitizenDashboardShell
    ? `${useFillViewport ? "h-dvh" : "min-h-dvh"} flex flex-col overflow-x-hidden bg-[#F6F9FE] text-[#002D62]`
    : useOpsViewportLock
      ? "min-h-screen bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200 lg:flex lg:h-dvh lg:flex-col lg:overflow-hidden"
      : "min-h-screen bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200";
  const headerClassName = isCitizenDashboardShell
    ? "border-b border-[#002D62]/10 bg-white shadow-sm"
    : "border-b border-[#002D62]/10 bg-zinc-200/95 shadow-sm backdrop-blur-md";
  const headerInnerClassName = `${shellWidthClass} px-4 py-4 sm:px-6 lg:px-8 2xl:px-10 xl:py-5`;
  const headerRowClassName = isCitizenDashboardShell
    ? "flex items-center justify-between gap-2 sm:gap-3"
    : "flex flex-nowrap items-center justify-between gap-3";
  const headerTitleGroupClassName = isCitizenDashboardShell
    ? "flex min-w-0 items-center gap-3 sm:gap-4"
    : "flex min-w-0 items-center gap-3 sm:gap-4";
  const logoClassName =
    "shrink-0 bg-[#002D62] px-4 py-2.5 text-lg font-bold tracking-[-1px] text-white sm:px-5 sm:py-3 sm:text-xl";
  const titleClassName = isCitizenDashboardShell
    ? "truncate text-base font-bold text-[#002D62] min-[400px]:text-xl sm:text-2xl"
    : "truncate text-xl font-bold text-[#002D62] sm:text-2xl";
  const subtitleClassName = isCitizenDashboardShell
    ? "mt-0.5 truncate text-sm text-slate-500"
    : "mt-0.5 truncate text-sm text-gray-600";
  const actionsClassName = isCitizenDashboardShell
    ? "flex shrink-0 items-center gap-2"
    : "flex shrink-0 items-center gap-2 sm:gap-3";
  const logoutClassName = isCitizenDashboardShell
    ? "inline-flex h-10 w-10 shrink-0 items-center justify-center gap-2 rounded-xl border border-[#0B3FE8] bg-white px-0 text-sm font-bold text-[#002D62] transition-colors hover:bg-[#EFF6FF] min-[480px]:w-[6.5rem] min-[480px]:px-3"
    : "inline-flex items-center gap-2 rounded-2xl border-2 border-[#002D62] bg-white px-4 py-2 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF]";
  const contentOuterClassName = isCitizenDashboardShell
    ? useFillViewport
      ? `${shellWidthClass} flex min-h-0 w-full flex-1 flex-col px-4 pb-4 pt-3 sm:px-6 lg:px-8 2xl:px-10`
      : `${shellWidthClass} w-full px-4 py-3 sm:px-6 lg:px-8 2xl:px-10`
    : useOpsViewportLock
      ? `${shellWidthClass} flex min-h-0 w-full flex-1 flex-col px-4 pt-0 pb-6 sm:px-6 lg:px-8 lg:pb-4 2xl:px-10`
      : `${shellWidthClass} w-full px-4 py-6 sm:px-6 lg:px-8 2xl:px-10`;
  const contentInnerClassName = [
    "min-w-0 w-full",
    useViewportFill ? "flex min-h-0 flex-1 flex-col" : "",
    contentClassName,
  ]
    .filter(Boolean)
    .join(" ");

  const accountActions = (
    <>
      {role === "citizen" ? (
        <ProfileMenu compactOnMobile />
      ) : (
        <Link
          href="/dashboard/profile"
          className="inline-flex items-center gap-2 rounded-2xl border-2 border-[#002D62] bg-white px-4 py-2 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
        >
          <User className="h-4 w-4" aria-hidden />
          Profile
        </Link>
      )}
      {onLogout ? (
        <button
          type="button"
          onClick={onLogout}
          className={logoutClassName}
        >
          <LogOut className="h-4 w-4" aria-hidden />
          <span className={isCitizenDashboardShell ? "sr-only min-[480px]:not-sr-only" : ""}>
            Logout
          </span>
        </button>
      ) : null}
    </>
  );

  const shellContent = (
    <>
      <div className={`${headerClassName}${useViewportFill ? " shrink-0" : ""}`}>
        <div className={headerInnerClassName}>
          <div className={headerRowClassName}>
            <div className={headerTitleGroupClassName}>
              <Link
                href="/"
                className={logoClassName}
              >
                NIERS
              </Link>
              <div className="min-w-0">
                {hideSidebar ? (
                  <>
                    <h1 className="hidden truncate text-3xl font-bold text-[#002D62] xl:block">
                      {title}
                    </h1>
                    <h1 className="truncate text-xl font-bold text-[#002D62] xl:hidden">
                      {title}
                    </h1>
                  </>
                ) : (
                  <h1 className={titleClassName}>
                    {isCitizenDashboardShell ? (
                      <>
                        <span className="min-[400px]:hidden">Citizen Portal</span>
                        <span className="hidden min-[400px]:inline">{title}</span>
                      </>
                    ) : (
                      title
                    )}
                  </h1>
                )}
                <p
                  className={`${subtitleClassName} ${
                    hideSidebar ? "hidden xl:block" : "hidden md:block"
                  }`}
                >
                  {subtitle}
                </p>
              </div>
            </div>
            <div className={actionsClassName}>
              {!isCitizenDashboardShell && showHealthBadge ? (
                <HealthBadge />
              ) : null}
              <NotificationBell />
              {accountActions}
            </div>
          </div>
        </div>
      </div>

      {showCitizenDisasterAlert ? <CitizenNationalDisasterAlert /> : null}
      {showOpsDisasterAlert ? (
        <OpsNationalDisasterAlertBar role={role} />
      ) : null}

      {showCitizenTopNav ? (
        <>
          <CitizenTopNav showReportAction={showCitizenReportAction} />
          <CitizenNavDrawer showReportAction={showCitizenReportAction} />
        </>
      ) : null}

      <div className={contentOuterClassName}>
        <div className={contentInnerClassName}>{children}</div>
      </div>
    </>
  );

  return (
    <div className={shellClassName}>
      {showCitizenTopNav ? (
        <CitizenNavProvider>{shellContent}</CitizenNavProvider>
      ) : (
        shellContent
      )}
    </div>
  );
};
