"use client";

import type { ReactNode } from "react";
import { AgencyNavProvider } from "@/components/agency/AgencyNavContext";
import { AgencyOpsDrawer } from "@/components/agency/AgencyOpsDrawer";
import { AgencyOpsNav } from "@/components/agency/AgencyOpsNav";

interface AgencyOpsShellProps {
  children: ReactNode;
  className?: string;
  /**
   * Pull the shell up to cancel DashboardLayout content padding (`py-6`).
   * Disable when the parent uses `lockViewport` (content area has `pt-0`).
   */
  cancelContentPadding?: boolean;
}

export function AgencyOpsShell({
  children,
  className = "",
  cancelContentPadding = false,
}: AgencyOpsShellProps) {
  return (
    <AgencyNavProvider>
      <div
        className={`-mx-4 ${cancelContentPadding ? "-mt-6" : ""} flex min-h-0 flex-1 flex-col overflow-x-hidden sm:-mx-6 lg:-mx-8 lg:h-full 2xl:-mx-10`}
      >
        <AgencyOpsNav />
        <AgencyOpsDrawer />
        <div
          className={`flex min-h-0 flex-1 flex-col bg-gradient-to-b from-slate-50 via-[#F4F7FB] to-sky-50/40 px-4 py-4 sm:px-6 lg:px-8 ${className}`}
        >
          {children}
        </div>
      </div>
    </AgencyNavProvider>
  );
}
