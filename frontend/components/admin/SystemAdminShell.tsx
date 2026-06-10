"use client";

import type { ReactNode } from "react";
import { SystemAdminNavProvider } from "@/components/admin/SystemAdminNavContext";
import { SystemAdminDrawer } from "@/components/admin/SystemAdminDrawer";
import { SystemAdminNav } from "@/components/admin/SystemAdminNav";

interface SystemAdminShellProps {
  children: ReactNode;
  className?: string;
  /** When true, shell fills the viewport (list workspaces). Overview uses natural height. */
  fillViewport?: boolean;
  /**
   * Pull the shell up to cancel DashboardLayout content padding (`py-6`).
   * Disable when the parent uses `lockViewport` (content area has `pt-0`).
   */
  cancelContentPadding?: boolean;
}

export function SystemAdminShell({
  children,
  className = "",
  fillViewport = false,
  cancelContentPadding = true,
}: SystemAdminShellProps) {
  return (
    <SystemAdminNavProvider>
      <div
        className={`-mx-4 ${cancelContentPadding ? "-mt-6" : ""} flex flex-col overflow-x-hidden sm:-mx-6 lg:-mx-8 2xl:-mx-10 ${
          fillViewport ? "min-h-0 flex-1 lg:h-full" : ""
        }`}
      >
        <SystemAdminNav />
        <SystemAdminDrawer />
        <div
          className={`flex min-h-0 flex-1 flex-col bg-gradient-to-b from-slate-50 via-[#F4F7FB] to-sky-50/40 px-4 py-4 sm:px-6 lg:px-8 ${className}`}
        >
          {children}
        </div>
      </div>
    </SystemAdminNavProvider>
  );
}
