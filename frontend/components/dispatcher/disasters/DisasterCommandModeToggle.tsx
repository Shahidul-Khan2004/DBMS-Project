"use client";

import Link from "next/link";
import { getDisasterSegmentActiveClasses } from "@/components/dispatcher/disasters/disasterColors";
import {
  dispatcherNationalDisasterLinkReportsPath,
  dispatcherNationalDisasterOverviewPath,
  type DisasterCommandMode,
} from "@/lib/dispatcher-national-disaster-routes";

const MODE_OPTIONS: { value: DisasterCommandMode; label: string }[] = [
  { value: "overview", label: "Overview" },
  { value: "link-reports", label: "Link Reports" },
];

export function DisasterCommandModeToggle({
  mode,
  disasterPublicUuid,
}: {
  mode: DisasterCommandMode;
  disasterPublicUuid: string;
}) {
  const overviewPath = dispatcherNationalDisasterOverviewPath(disasterPublicUuid);
  const linkReportsPath =
    dispatcherNationalDisasterLinkReportsPath(disasterPublicUuid);

  return (
    <div
      role="tablist"
      aria-label="Disaster command mode"
      className="inline-flex max-w-full flex-wrap gap-1 rounded-lg border border-slate-200 bg-slate-50/80 p-1"
    >
      {MODE_OPTIONS.map((option) => {
        const isActive = mode === option.value;
        const href =
          option.value === "overview" ? overviewPath : linkReportsPath;
        return (
          <Link
            key={option.value}
            href={href}
            role="tab"
            aria-selected={isActive}
            className={`inline-flex shrink-0 cursor-pointer items-center rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              isActive
                ? getDisasterSegmentActiveClasses()
                : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
            }`}
          >
            {option.label}
          </Link>
        );
      })}
    </div>
  );
}
