"use client";

import dynamic from "next/dynamic";
import type { IntakeLocation } from "@/components/dispatcher/triage/types";
import {
  formatReportedCoordinates,
  getValidReportedCoordinates,
} from "@/components/dispatcher/triage/reportedLocationCoords";
import { Button } from "@/components/ui/Button";

const MAP_PREVIEW_HEIGHT_CLASS = "h-48 max-h-56 min-h-40";

const ReportedLocationMapPreview = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.ReportedLocationMapPreview }),
    ),
  {
    ssr: false,
    loading: () => (
      <div
        className={`${MAP_PREVIEW_HEIGHT_CLASS} w-full animate-pulse rounded-lg bg-slate-100`}
      />
    ),
  },
);

interface ReportedLocationDisplayProps {
  location: IntakeLocation;
  label?: string;
  supportingText?: string;
  editLabel?: string;
  showViewHistory?: boolean;
  /** Stable report id for Leaflet remount when switching intakes */
  previewKey?: string;
  /** Text-only display without map preview (active route forms) */
  compact?: boolean;
  onEditLocation?: () => void;
  onViewHistory?: () => void;
}

export function ReportedLocationDisplay({
  location,
  label = "Reported Location",
  supportingText,
  editLabel = "Edit Location",
  showViewHistory = true,
  previewKey,
  compact = false,
  onEditLocation,
  onViewHistory,
}: ReportedLocationDisplayProps) {
  const coordinates = getValidReportedCoordinates(
    location.latitude,
    location.longitude,
  );
  const placeName = location.areaName?.trim() ?? "";
  const showPlaceName =
    placeName.length > 0 && placeName !== location.addressText?.trim();
  const showActions =
    onEditLocation || (showViewHistory && onViewHistory);

  return (
    <section>
      <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        {label}
      </h4>
      {supportingText ? (
        <p className="mt-0.5 text-xs text-slate-500">{supportingText}</p>
      ) : null}
      {!compact ? (
        <div className="mt-1.5">
          <ReportedLocationMapPreview
            previewKey={previewKey}
            latitude={location.latitude}
            longitude={location.longitude}
            addressText={location.addressText}
            placeName={location.areaName}
            heightClassName={MAP_PREVIEW_HEIGHT_CLASS}
          />
        </div>
      ) : null}
      <div
        className={`${compact ? "mt-1" : "mt-1.5"} flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between`}
      >
        <div className="min-w-0 flex-1">
          <p className="text-sm text-slate-900">{location.addressText}</p>
          {showPlaceName ? (
            <p className="mt-0.5 text-xs text-slate-500">{placeName}</p>
          ) : null}
          {coordinates ? (
            <p className="mt-0.5 text-xs text-slate-500">
              {formatReportedCoordinates(
                coordinates.latitude,
                coordinates.longitude,
              )}
            </p>
          ) : null}
        </div>
        {showActions ? (
          <div className="flex shrink-0 flex-wrap gap-2 sm:justify-end">
            {onEditLocation ? (
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={onEditLocation}
              >
                {editLabel}
              </Button>
            ) : null}
            {showViewHistory && onViewHistory ? (
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={onViewHistory}
              >
                View History
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
