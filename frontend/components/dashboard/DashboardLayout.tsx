"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect, useState } from "react";
import { getAuthSession, type UserRole } from "@/lib/auth-store";
import { LogOut } from "lucide-react";
import { HealthBadge } from "@/components/HealthBadge";

interface DashboardLayoutProps {
  title: string;
  subtitle: string;
  children: React.ReactNode;
  onLogout?: () => void;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  title,
  subtitle,
  children,
  onLogout,
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
          { href: "/dashboard/citizen/locations", label: "Locations" },
        ]
      : []),
    ...(role === "dispatcher" || role === "system_admin"
      ? [
          { href: "/dashboard/dispatcher", label: "Overview" },
          { href: "/dashboard/dispatcher/gateway-999", label: "999 Gateway" },
          { href: "/dashboard/dispatcher/intake-reports", label: "Intake Queue" },
          { href: "/dashboard/dispatcher/service-cases", label: "Service Cases" },
          { href: "/dashboard/dispatcher/incidents", label: "Incidents" },
        ]
      : []),
    ...(role === "system_admin"
      ? [{ href: "/dashboard/admin", label: "Roles" }]
      : []),
    { href: "/dashboard/profile", label: "Profile" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200">
      {/* Header */}
      <div className="border-b border-[#002D62]/10 bg-zinc-200/95 shadow-sm backdrop-blur-md">
        <div className="mx-auto max-w-screen-2xl px-4 py-5 sm:px-6 lg:px-8 2xl:px-10">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              <Link href="/" className="shrink-0 bg-[#002D62] px-5 py-3 text-xl font-bold tracking-[-1px] text-white">
                NIERS
              </Link>
              <div>
                <h1 className="text-2xl font-bold text-[#002D62]">{title}</h1>
                <p className="mt-1 text-sm text-gray-600">{subtitle}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <HealthBadge />
              {onLogout && (
                <button
                  onClick={onLogout}
                  className="inline-flex items-center gap-2 rounded-2xl border-2 border-[#002D62] bg-white px-4 py-2 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
                >
                  <LogOut className="h-4 w-4" aria-hidden />
                  Logout
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="mx-auto grid max-w-screen-2xl items-start gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[220px_minmax(0,1fr)] lg:px-8 2xl:px-10">
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
        <div className="min-w-0">{children}</div>
      </div>
    </div>
  );
};
