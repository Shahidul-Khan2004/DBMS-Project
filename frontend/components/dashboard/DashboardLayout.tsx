"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect, useState } from "react";
import { getAuthSession, type UserRole } from "@/lib/auth-store";
import {
  AlertTriangle,
  ArrowLeft,
  ClipboardCheck,
  FileText,
  LayoutGrid,
  LogOut,
  MapPin,
  Plus,
  User,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { HealthBadge } from "@/components/HealthBadge";
import { ProfileMenu } from "@/components/dashboard/ProfileMenu";
import { NotificationBell } from "@/components/notifications/NotificationBell";

interface DashboardLayoutProps {
  title: string;
  subtitle: string;
  children: React.ReactNode;
  onLogout?: () => void;
  hideSidebar?: boolean;
  showHealthBadge?: boolean;
  /** Applied to the main content children wrapper (e.g. full-height dispatcher pages). */
  contentClassName?: string;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  title,
  subtitle,
  children,
  onLogout,
  hideSidebar = false,
  showHealthBadge = true,
  contentClassName = "",
}) => {
  const pathname = usePathname();
  const [role, setRole] = useState<UserRole>("citizen");

  useEffect(() => {
    const nextRole = getAuthSession().userRole;
    queueMicrotask(() => setRole(nextRole));
  }, []);

  const navItems = [
    ...(role === "citizen"
      ? [
          { href: "/dashboard/citizen", label: "Dashboard", icon: LayoutGrid },
          { href: "/dashboard/citizen/reports", label: "My Reports", icon: FileText },
          { href: "/dashboard/citizen/service-cases", label: "Service Cases", icon: ClipboardCheck },
          { href: "/dashboard/citizen/incidents", label: "My Incidents", icon: AlertTriangle },
          { href: "/dashboard/citizen/locations", label: "Locations", icon: MapPin },
        ]
      : []),
    ...(role === "system_admin"
      ? [{ href: "/dashboard/admin", label: "Admin", icon: LayoutGrid }]
      : []),
  ] satisfies Array<{ href: string; label: string; icon: LucideIcon }>;

  const isCitizenDashboardRoute = pathname.startsWith("/dashboard/citizen");
  const isCitizenSharedRoute =
    pathname === "/dashboard/profile" || pathname === "/dashboard/notifications";
  const isCitizenDashboardShell =
    role === "citizen" && (isCitizenDashboardRoute || isCitizenSharedRoute);
  const showCitizenTopNav =
    isCitizenDashboardShell && !hideSidebar;
  const isCitizenReportNewPage = pathname === "/dashboard/citizen/report-new";
  const showCitizenReportAction = !isCitizenReportNewPage;
  const shellWidthClass = "w-full";
  const shellClassName = isCitizenDashboardShell
    ? "min-h-screen bg-[#F6F9FE] text-[#002D62]"
    : "min-h-screen bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200";
  const headerClassName = isCitizenDashboardShell
    ? "border-b border-[#002D62]/10 bg-white shadow-sm"
    : "border-b border-[#002D62]/10 bg-zinc-200/95 shadow-sm backdrop-blur-md";
  const headerInnerClassName = isCitizenDashboardShell
    ? `${shellWidthClass} px-6 py-4 sm:px-8 lg:px-10 2xl:px-12`
    : `${shellWidthClass} px-4 py-4 sm:px-6 lg:px-8 2xl:px-10 xl:py-5`;
  const headerRowClassName = isCitizenDashboardShell
    ? "flex flex-wrap items-center justify-between gap-4"
    : "flex flex-nowrap items-center justify-between gap-3";
  const headerTitleGroupClassName = isCitizenDashboardShell
    ? "flex min-w-0 items-center gap-5"
    : "flex min-w-0 items-center gap-3 sm:gap-4";
  const logoClassName = isCitizenDashboardShell
    ? "flex h-14 w-[116px] shrink-0 items-center justify-center bg-[#002D62] text-2xl font-bold text-white shadow-sm"
    : "shrink-0 bg-[#002D62] px-4 py-2.5 text-lg font-bold tracking-[-1px] text-white sm:px-5 sm:py-3 sm:text-xl";
  const titleClassName = isCitizenDashboardShell
    ? "truncate text-2xl font-bold text-[#002D62] sm:text-[30px]"
    : "truncate text-xl font-bold text-[#002D62] sm:text-2xl";
  const subtitleClassName = isCitizenDashboardShell
    ? "mt-1 truncate text-base text-slate-500"
    : "mt-0.5 truncate text-sm text-gray-600";
  const actionsClassName = isCitizenDashboardShell
    ? "flex shrink-0 items-center gap-4"
    : "flex shrink-0 items-center gap-2 sm:gap-3";
  const logoutClassName = isCitizenDashboardShell
    ? "inline-flex h-12 items-center gap-2 rounded-xl border-2 border-[#0B3FE8] bg-white px-5 text-sm font-bold text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
    : "inline-flex items-center gap-2 rounded-2xl border-2 border-[#002D62] bg-white px-4 py-2 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF]";
  const contentOuterClassName = isCitizenDashboardShell
    ? `${shellWidthClass} w-full px-6 py-6 sm:px-8 lg:px-10 2xl:px-12`
    : `${shellWidthClass} w-full px-4 py-6 sm:px-6 lg:px-8 2xl:px-10`;

  const accountActions = (
    <>
      {role === "citizen" ? (
        <ProfileMenu />
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
          Logout
        </button>
      ) : null}
    </>
  );

  return (
    <div className={shellClassName}>
      <div className={headerClassName}>
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
                    {title}
                  </h1>
                )}
                <p
                  className={`${subtitleClassName} ${
                    hideSidebar ? "hidden xl:block" : "hidden sm:block"
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

      {showCitizenTopNav ? (
        <div className="border-b border-[#002D62]/10 bg-white">
          <div className={`${shellWidthClass} px-6 sm:px-8 lg:px-10 2xl:px-12`}>
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <nav
                className="flex max-w-full gap-6 overflow-x-auto lg:gap-12"
                aria-label="Citizen dashboard navigation"
              >
                {navItems.map((item) => {
                  const active =
                    pathname === item.href ||
                    (item.href !== "/dashboard/citizen" &&
                      pathname.startsWith(item.href));
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`relative inline-flex h-[72px] shrink-0 items-center gap-3 whitespace-nowrap px-2 text-sm font-semibold transition-colors ${
                        active
                          ? "text-[#0B3FE8]"
                          : "text-[#1F3768] hover:text-[#0B3FE8]"
                      }`}
                    >
                      <Icon className="h-5 w-5" aria-hidden />
                      {item.label}
                      {active ? (
                        <span className="absolute inset-x-0 bottom-0 h-1 rounded-t-full bg-[#0B3FE8]" />
                      ) : null}
                    </Link>
                  );
                })}
              </nav>
              {isCitizenReportNewPage ? (
                <Link
                  href="/dashboard/citizen"
                  className="mb-2 inline-flex h-14 shrink-0 items-center justify-center gap-3 rounded-lg border border-[#002D62]/20 bg-white px-7 text-base font-bold text-[#002D62] shadow-sm transition-colors hover:bg-[#EFF6FF] lg:mb-0"
                >
                  <ArrowLeft className="h-5 w-5" aria-hidden />
                  Back to Dashboard
                </Link>
              ) : showCitizenReportAction ? (
                <Link
                  href="/dashboard/citizen/report-new"
                  className="mb-2 inline-flex h-14 shrink-0 items-center justify-center gap-3 rounded-lg bg-[#B91C1C] px-9 text-base font-bold text-white shadow-lg shadow-[#B91C1C]/20 transition-colors hover:bg-[#991B1B] lg:mb-0"
                >
                  <Plus className="h-5 w-5" aria-hidden />
                  Report New Incident
                </Link>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      <div
        className={contentOuterClassName}
      >
        <div className={`min-w-0 w-full ${contentClassName}`.trim()}>{children}</div>
      </div>
    </div>
  );
};
