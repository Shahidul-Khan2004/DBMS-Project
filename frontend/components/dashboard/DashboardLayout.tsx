"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect, useState } from "react";
import { getAuthSession, type UserRole } from "@/lib/auth-store";

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
    setRole(getAuthSession().userRole);
  }, []);

  const navItems = [
    ...(role === "citizen"
      ? [
          { href: "/dashboard/citizen", label: "Dashboard" },
          { href: "/dashboard/citizen/report-new", label: "New Report" },
          { href: "/dashboard/citizen/reports", label: "My Reports" },
        ]
      : []),
    ...(role === "dispatcher" || role === "system_admin"
      ? [
          { href: "/dashboard/dispatcher", label: "Overview" },
          { href: "/dashboard/dispatcher/intake-reports", label: "Intake Queue" },
          { href: "/dashboard/dispatcher/incidents", label: "Incidents" },
        ]
      : []),
    ...(role === "system_admin"
      ? [{ href: "/dashboard/admin", label: "Roles" }]
      : []),
    { href: "/dashboard/profile", label: "Profile" },
  ];

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <div className="border-b border-gray-200 bg-white shadow-sm">
        <div className="mx-auto max-w-6xl px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
              <p className="mt-1 text-sm text-gray-600">{subtitle}</p>
            </div>
            <div className="flex items-center gap-3">
              {onLogout && (
                <button
                  onClick={onLogout}
                  className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
                >
                  Logout
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="mx-auto grid max-w-6xl items-start gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[220px_1fr] lg:px-8">
        <nav className="flex max-w-full gap-2 overflow-x-auto rounded-xl border border-slate-200 bg-white/95 p-2 shadow-sm ring-1 ring-slate-100 lg:sticky lg:top-6 lg:block lg:space-y-1.5 lg:overflow-visible">
          {navItems.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`block shrink-0 whitespace-nowrap rounded-lg px-3 py-2.5 text-sm font-medium transition-colors lg:w-full ${
                  active
                    ? "bg-blue-600 text-white shadow-sm"
                    : "text-slate-700 hover:bg-slate-100 hover:text-slate-950"
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
