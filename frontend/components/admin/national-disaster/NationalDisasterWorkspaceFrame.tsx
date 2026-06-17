"use client";

import type { ReactNode } from "react";
import { NationalDisasterSectionSwitch } from "@/components/admin/national-disaster/NationalDisasterSubnav";

type NationalDisasterWorkspaceFrameProps = {
  children: ReactNode;
  /** Hub pages only (landing, facility registry list). Hidden on drill-down views with back links. */
  showSectionSwitch?: boolean;
  /** Let content grow with the page scroll area (forms, detail views). */
  scrollable?: boolean;
};

export function NationalDisasterWorkspaceFrame({
  children,
  showSectionSwitch = false,
  scrollable = false,
}: NationalDisasterWorkspaceFrameProps) {
  return (
    <div
      className={`flex flex-col gap-2 ${
        scrollable ? "min-h-0" : "min-h-0 flex-1 lg:overflow-hidden"
      }`}
    >
      {showSectionSwitch ? (
        <div className="shrink-0">
          <NationalDisasterSectionSwitch />
        </div>
      ) : null}
      {children}
    </div>
  );
}
