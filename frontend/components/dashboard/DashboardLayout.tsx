"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect, useState } from "react";
import { getAuthSession, type UserRole } from "@/lib/auth-store";
import { LogOut, User } from "lucide-react";
import { HealthBadge } from "@/components/HealthBadge";
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
          { href: "/dashboard/citizen", label: "Dashboard" },
          { href: "/dashboard/citizen/report-new", label: "New Report" },
          { href: "/dashboard/citizen/reports", label: "My Reports" },
          { href: "/dashboard/citizen/service-cases", label: "Service Cases" },
          { href: "/dashboard/citizen/incidents", label: "My Incidents" },
          { href: "/dashboard/citizen/locations", label: "Locations" },
        ]
      : []),
    ...(role === "system_admin"
      ? [{ href: "/dashboard/admin", label: "Admin" }]
      : []),
    { href: "/dashboard/profile", label: "Profile" },
  ];

  const showLegacySidebar = role === "citizen" && !hideSidebar;
  const isAdminConsole =
    pathname?.startsWith("/dashboard/admin") ?? false;
  const shellWidthClass = isAdminConsole
    ? "w-full"
    : "mx-auto max-w-screen-2xl";

  const accountActions = (
    <>
      <Link
        href="/dashboard/profile"
        className="inline-flex items-center gap-2 rounded-2xl border-2 border-[#002D62] bg-white px-4 py-2 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
      >
        <User className="h-4 w-4" aria-hidden />
        Profile
      </Link>
      {onLogout ? (
        <button
          type="button"
          onClick={onLogout}
          className="inline-flex items-center gap-2 rounded-2xl border-2 border-[#002D62] bg-white px-4 py-2 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
        >
          <LogOut className="h-4 w-4" aria-hidden />
          Logout
        </button>
      ) : null}
    </>
  );

  return (
    <div className="min-h-screen bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200">
      <div className="border-b border-[#002D62]/10 bg-zinc-200/95 shadow-sm backdrop-blur-md">
        <div
          className={`${shellWidthClass} px-4 py-4 sm:px-6 lg:px-8 2xl:px-10 xl:py-5`}
        >
          <div className="flex flex-nowrap items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-3 sm:gap-4">
              <Link
                href="/"
                className="shrink-0 bg-[#002D62] px-4 py-2.5 text-lg font-bold tracking-[-1px] text-white sm:px-5 sm:py-3 sm:text-xl"
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
                  <h1 className="truncate text-xl font-bold text-[#002D62] sm:text-2xl">
                    {title}
                  </h1>
                )}
                <p
                  className={`mt-0.5 truncate text-sm text-gray-600 ${
                    hideSidebar ? "hidden xl:block" : "hidden sm:block"
                  }`}
                >
                  {subtitle}
                </p>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2 sm:gap-3">
              {showHealthBadge ? <HealthBadge /> : null}
              <NotificationBell />
              {accountActions}
            </div>
          </div>
        </div>
      </div>

      <div
        className={
          showLegacySidebar
            ? `${shellWidthClass} grid items-start gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[220px_minmax(0,1fr)] lg:px-8 2xl:px-10`
            : `${shellWidthClass} w-full px-4 py-6 sm:px-6 lg:px-8 2xl:px-10`
        }
      >
        {showLegacySidebar ? (
          <nav className="flex max-w-full gap-2 overflow-x-auto rounded-3xl border border-[#002D62]/10 bg-zinc-200/95 p-2 shadow-lg shadow-[#002D62]/5 lg:sticky lg:top-6 lg:block lg:space-y-1.5 lg:overflow-visible">
            {navItems.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`block shrink-0 whitespace-nowrap rounded-lg px-3 py-2.5 text-sm font-medium transition-colors lg:w-full ${
                    active
                      ? "bg-[#002D62] text-white shadow-sm"
                      : "text-slate-700 hover:bg-[#EFF6FF] hover:text-[#006747]"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        ) : null}
        <div className={`min-w-0 w-full ${contentClassName}`.trim()}>{children}</div>
      </div>
    </div>
  );
};
