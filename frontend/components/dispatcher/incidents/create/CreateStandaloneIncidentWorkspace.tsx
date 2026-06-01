"use client";

import type { ReactNode } from "react";

type CreateStandaloneIncidentWorkspaceProps = {
  pageHeader: ReactNode;
  detailsPanel: ReactNode;
  locationPanel: ReactNode;
};

export function CreateStandaloneIncidentWorkspace({
  pageHeader,
  detailsPanel,
  locationPanel,
}: CreateStandaloneIncidentWorkspaceProps) {
  return (
    <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:h-full lg:grid-cols-2 lg:items-stretch lg:gap-3 lg:overflow-hidden">
      <div className="flex min-h-0 flex-col gap-3">
        {pageHeader}
        <div className="flex min-h-0 flex-1 flex-col">{detailsPanel}</div>
      </div>
      <div className="flex min-h-0 flex-col lg:h-full">{locationPanel}</div>
    </div>
  );
}
