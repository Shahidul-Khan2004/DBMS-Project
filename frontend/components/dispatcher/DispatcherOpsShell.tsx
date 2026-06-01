"use client";

import type { ReactNode } from "react";
import { DispatcherNavProvider } from "@/components/dispatcher/DispatcherNavContext";
import { DispatcherOpsDrawer } from "@/components/dispatcher/DispatcherOpsDrawer";
import { DispatcherAdminOversightBar } from "@/components/dispatcher/DispatcherAdminOversightBar";
import { DispatcherOpsNav } from "@/components/dispatcher/DispatcherOpsNav";

interface DispatcherOpsShellProps {
  children: ReactNode;
  className?: string;
}

export function DispatcherOpsShell({
  children,
  className = "",
}: DispatcherOpsShellProps) {
  return (
    <DispatcherNavProvider>
      <div className="-mx-4 -mt-6 flex min-h-[calc(100vh-8rem)] flex-col overflow-x-hidden sm:-mx-6 lg:-mx-8 2xl:-mx-10">
        <DispatcherAdminOversightBar />
        <DispatcherOpsNav />
        <DispatcherOpsDrawer />
        <div
          className={`flex min-h-0 flex-1 flex-col bg-gradient-to-b from-slate-50 via-[#F4F7FB] to-sky-50/40 px-4 py-4 sm:px-6 lg:px-8 ${className}`}
        >
          {children}
        </div>
      </div>
    </DispatcherNavProvider>
  );
}
