"use client";

import dynamic from "next/dynamic";
import { useState } from "react";
import { formatFacilityLocationSummary } from "@/lib/admin-facility-format";
import type { FacilityLocation } from "@/types/admin-facility";

const MAP_HEIGHT_CLASS = "h-44 w-full";

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
  /** When true (default), map is hidden until user expands. */
  compact?: boolean;
};

export function DisasterLocationDisplay({
  location,
  className = "",
  compact = true,
}: DisasterLocationDisplayProps) {
  const [mapOpen, setMapOpen] = useState(false);
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

  if (!compact) {
    return (
      <div className={`space-y-2 ${className}`}>
        {summary ? (
          <p className="text-xs text-slate-600">{summary}</p>
        ) : null}
        {hasCoords ? (
          <ReportedLocationMapPreview
            latitude={lat}
            longitude={lng}
            heightClassName={MAP_HEIGHT_CLASS}
            className={MAP_HEIGHT_CLASS}
          />
        ) : null}
      </div>
    );
  }

  return (
    <div className={`space-y-1 ${className}`}>
      {summary ? (
        <p className="text-xs text-slate-600">{summary}</p>
      ) : null}
      {hasCoords ? (
        <>
          <button
            type="button"
            onClick={() => setMapOpen((open) => !open)}
            className="text-xs font-medium text-[#002D62] hover:underline"
          >
            {mapOpen ? "Hide map" : "View map"}
          </button>
          {mapOpen ? (
            <ReportedLocationMapPreview
              latitude={lat}
              longitude={lng}
              heightClassName={MAP_HEIGHT_CLASS}
              className={`${MAP_HEIGHT_CLASS} rounded-lg overflow-hidden`}
            />
          ) : null}
        </>
      ) : null}
    </div>
  );
}
