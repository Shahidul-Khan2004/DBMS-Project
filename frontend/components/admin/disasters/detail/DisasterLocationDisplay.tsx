"use client";

import dynamic from "next/dynamic";
import { formatFacilityLocationSummary } from "@/lib/admin-facility-format";
import type { FacilityLocation } from "@/types/admin-facility";

const MAP_HEIGHT_CLASS = "h-[180px] w-full min-h-[160px]";

const ReportedLocationMapPreview = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.ReportedLocationMapPreview }),
    ),
  {
    ssr: false,
    loading: () => (
      <div
        className={`${MAP_HEIGHT_CLASS} animate-pulse rounded-lg bg-slate-100`}
      />
    ),
  },
);

type DisasterLocationDisplayProps = {
  location?: FacilityLocation | null;
  className?: string;
};

export function DisasterLocationDisplay({
  location,
  className = "",
}: DisasterLocationDisplayProps) {
  const summary = formatFacilityLocationSummary(location);
  const lat = location?.latitude;
  const lng = location?.longitude;
  const hasCoords =
    typeof lat === "number" &&
    typeof lng === "number" &&
    Number.isFinite(lat) &&
    Number.isFinite(lng);

  if (!summary && !hasCoords) {
    return <p className="text-xs text-slate-500">No location recorded</p>;
  }

  return (
    <div className={`space-y-2 ${className}`}>
      {summary ? (
        <p className="text-xs text-slate-600">{summary}</p>
      ) : null}
      {hasCoords ? (
        <div className="hidden lg:block">
          <ReportedLocationMapPreview
            latitude={lat}
            longitude={lng}
            heightClassName={MAP_HEIGHT_CLASS}
            className={MAP_HEIGHT_CLASS}
          />
        </div>
      ) : null}
    </div>
  );
}
