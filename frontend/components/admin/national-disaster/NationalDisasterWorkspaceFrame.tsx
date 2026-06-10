"use client";

import type { ReactNode } from "react";
import { NationalDisasterSectionSwitch } from "@/components/admin/national-disaster/NationalDisasterSubnav";

type NationalDisasterWorkspaceFrameProps = {
  children: ReactNode;
  /** Hub pages only (landing, facility registry list). Hidden on drill-down views with back links. */
  showSectionSwitch?: boolean;
};

export function NationalDisasterWorkspaceFrame({
  children,
  showSectionSwitch = false,
}: NationalDisasterWorkspaceFrameProps) {
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 lg:overflow-hidden">
      {showSectionSwitch ? (
        <div className="shrink-0">
          <NationalDisasterSectionSwitch />
        </div>
      ) : null}
      {children}
    </div>
  );
}
